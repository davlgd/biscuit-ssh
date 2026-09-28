//! Sandbox lifecycle: create, renew, delete, and reap what expired.
//!
//! State transitions are persisted before the Docker operation they
//! announce, and completed after it, so a crash anywhere leaves either
//! nothing or an entry the next start finishes: `Creating` entries are
//! undone, `Deleting` ones completed, and containers of this instance that
//! the state does not know are removed.
//!
//! A sandbox lives as long as its token: the token expires at
//! `expires_at - 1` (Biscuit expirations are inclusive), and the reaper
//! removes the container from `expires_at`, within [`REAP_INTERVAL`].

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_ssh_core::{Mode, Network, Restriction, Right, inspect, mint};
use bollard::Docker;
use tokio::sync::{Mutex, Semaphore};

use crate::config::Settings;
use crate::docker::{self, PullError};
use crate::image::ImageRef;
use crate::state::{Sandbox, Status, Store};

/// How often expired sandboxes are looked for.
pub const REAP_INTERVAL: Duration = Duration::from_secs(10);

/// Longest a container removal may take.
const REMOVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest a container may take to be created, started and checked.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// Why an operation failed; messages are fixed, never Docker's own.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// No such sandbox (or it already expired).
    #[error("sandbox not found")]
    NotFound,
    /// The request does not fit the sandbox's current state.
    #[error("{0}")]
    Conflict(&'static str),
    /// Too many sandboxes, or creations in progress.
    #[error("too many sandboxes, retry later")]
    TooMany,
    /// The requested lifetime is out of bounds.
    #[error("ttl must be between 60 and {0} seconds")]
    Ttl(u64),
    /// The image does not exist on Docker Hub.
    #[error("image not found")]
    ImageNotFound,
    /// The image cannot run as a sandbox.
    #[error("image not usable: it must be a Linux image with /bin/sh whose command keeps running")]
    ImageUnusable,
    /// Docker Hub failed or timed out.
    #[error("cannot pull the image, retry later")]
    Registry,
    /// Docker failed; the operation is retried or can be.
    #[error("service unavailable, retry later")]
    Unavailable,
}

/// A sandbox and the token giving access to it.
pub struct Lease {
    /// Container and server name.
    pub name: String,
    /// Canonical image reference.
    pub image: String,
    /// ID of the image the container runs.
    pub image_id: String,
    /// First second the token no longer allows, since the Unix epoch.
    pub expires_at: u64,
    /// The client address the token is restricted to.
    pub client: IpAddr,
    /// The token.
    pub token: String,
}

/// Sandboxes, their state and Docker.
pub struct Sandboxes {
    docker: Docker,
    settings: Settings,
    store: Mutex<Store>,
    creations: Semaphore,
}

impl Sandboxes {
    /// Manages sandboxes with `store`.
    pub fn new(docker: Docker, settings: Settings, store: Store) -> Self {
        let creations = Semaphore::new(settings.max_creations);
        Self {
            docker,
            settings,
            store: Mutex::new(store),
            creations,
        }
    }

    /// The service's settings.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Finishes what a previous run left: undoes creations, then reaps.
    pub async fn recover(&self) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        let creating: Vec<String> = store
            .state
            .sandboxes
            .iter()
            .filter(|(_, sandbox)| sandbox.status == Status::Creating)
            .map(|(name, _)| name.clone())
            .collect();
        if !creating.is_empty() {
            let instance = store.state.instance.clone();
            for (id, name) in docker::list(&self.docker, &self.settings.label, &instance).await? {
                if creating.contains(&name) {
                    docker::remove(&self.docker, &id).await?;
                }
            }
            store.state.sandboxes.retain(|name, _| !creating.contains(name));
            store.save(now())?;
        }
        drop(store);
        self.reap().await;
        Ok(())
    }

    /// Creates a sandbox running `image`, for `client`.
    pub async fn create(&self, image: &ImageRef, ttl: Option<u64>, client: IpAddr) -> Result<Lease, Failure> {
        let ttl = self.ttl(ttl)?;
        let _creating = self.creations.try_acquire().map_err(|_| Failure::TooMany)?;
        let name = format!(
            "sb-{}",
            random_hex().map_err(|e| {
                tracing::error!(error = %e, "cannot name a sandbox");
                Failure::Unavailable
            })?
        );
        let instance = {
            let mut store = self.store.lock().await;
            if store.state.sandboxes.len() >= self.settings.max_sandboxes {
                return Err(Failure::TooMany);
            }
            store.state.sandboxes.insert(
                name.clone(),
                Sandbox {
                    status: Status::Creating,
                    image: image.to_string(),
                    container: None,
                    image_id: None,
                    token: None,
                    expires_at: 0,
                    client,
                },
            );
            save(&mut store)?;
            store.state.instance.clone()
        };

        let provisioned = self.provision(&name, image, &instance).await;
        let mut store = self.store.lock().await;
        let (container, image_id) = match provisioned {
            Ok(provisioned) => provisioned,
            Err(failure) => {
                store.state.sandboxes.remove(&name);
                save(&mut store)?;
                return Err(failure);
            }
        };
        // The announced lifetime counts from when the sandbox is ready.
        let expires_at = now() + ttl;
        let activated = self.token(&name, client, expires_at).and_then(|token| {
            let sandbox = store.state.sandboxes.get_mut(&name).ok_or(Failure::Unavailable)?;
            sandbox.status = Status::Active;
            sandbox.container = Some(container.clone());
            sandbox.image_id = Some(image_id.clone());
            sandbox.token = Some(token.id.clone());
            sandbox.expires_at = expires_at;
            save(&mut store)?;
            Ok(token)
        });
        let token = match activated {
            Ok(token) => token,
            Err(failure) => {
                let _ = docker::remove(&self.docker, &container).await;
                store.state.sandboxes.remove(&name);
                let _ = save(&mut store);
                return Err(failure);
            }
        };
        tracing::info!(%name, image = %image, %client, expires_at, "sandbox created");
        Ok(Lease {
            name,
            image: image.to_string(),
            image_id,
            expires_at,
            client,
            token: token.token,
        })
    }

    /// Pulls `image` and runs a checked container `name`; on failure,
    /// nothing is left running.
    async fn provision(&self, name: &str, image: &ImageRef, instance: &str) -> Result<(String, String), Failure> {
        let image_id = docker::pull(&self.docker, image, self.settings.pull_timeout)
            .await
            .map_err(|e| match e {
                PullError::NotFound => Failure::ImageNotFound,
                PullError::Platform => Failure::ImageUnusable,
                PullError::Registry | PullError::Timeout => Failure::Registry,
            })?;
        let label = (self.settings.label.as_str(), instance);
        let started = async {
            let container = docker::run(&self.docker, name, &image_id, label, &self.settings.limits).await?;
            let usable = docker::usable(&self.docker, &container, self.settings.account.as_str()).await;
            anyhow::Ok((container, usable))
        };
        match tokio::time::timeout(START_TIMEOUT, started).await {
            Ok(Ok((container, true))) => Ok((container, image_id)),
            Ok(Ok((container, false))) => {
                let _ = docker::remove(&self.docker, &container).await;
                Err(Failure::ImageUnusable)
            }
            Ok(Err(e)) => {
                tracing::warn!(%name, error = %e, "cannot run the container");
                self.remove_by_name(name, instance).await;
                Err(Failure::ImageUnusable)
            }
            Err(_) => {
                self.remove_by_name(name, instance).await;
                Err(Failure::Unavailable)
            }
        }
    }

    /// Removes this instance's container named `name`, if any; the name is
    /// checked against the instance label, and the removal made by ID.
    async fn remove_by_name(&self, name: &str, instance: &str) {
        if let Ok(containers) = docker::list(&self.docker, &self.settings.label, instance).await {
            for (id, _) in containers.into_iter().filter(|(_, n)| n == name) {
                let _ = docker::remove(&self.docker, &id).await;
            }
        }
    }

    /// Gives sandbox `name` a new token for `client`, living `ttl` from now;
    /// the previous token is revoked.
    pub async fn renew(&self, name: &str, ttl: Option<u64>, client: IpAddr) -> Result<Lease, Failure> {
        let ttl = self.ttl(ttl)?;
        let mut store = self.store.lock().await;
        let now = now();
        let sandbox = store.state.sandboxes.get(name).ok_or(Failure::NotFound)?;
        if sandbox.status != Status::Active || sandbox.expires_at <= now {
            return Err(Failure::NotFound);
        }
        let expires_at = now + ttl;
        if expires_at < sandbox.expires_at {
            return Err(Failure::Conflict("the renewal would shorten the sandbox's life"));
        }
        let (previous, previous_expiry) = (sandbox.token.clone(), sandbox.expires_at);
        let token = self.token(name, client, expires_at)?;
        if let Some(previous) = previous {
            store.state.revoked.insert(previous, previous_expiry);
        }
        let sandbox = store.state.sandboxes.get_mut(name).ok_or(Failure::NotFound)?;
        sandbox.token = Some(token.id);
        sandbox.expires_at = expires_at;
        sandbox.client = client;
        let lease = Lease {
            name: name.to_owned(),
            image: sandbox.image.clone(),
            image_id: sandbox.image_id.clone().unwrap_or_default(),
            expires_at,
            client,
            token: token.token,
        };
        save(&mut store)?;
        tracing::info!(%name, %client, expires_at, "sandbox renewed");
        Ok(lease)
    }

    /// Revokes the token of sandbox `name` and removes its container.
    pub async fn delete(&self, name: &str) -> Result<(), Failure> {
        let container = {
            let mut store = self.store.lock().await;
            let sandbox = store.state.sandboxes.get_mut(name).ok_or(Failure::NotFound)?;
            if sandbox.status == Status::Creating {
                return Err(Failure::Conflict("the sandbox is still being created"));
            }
            sandbox.status = Status::Deleting;
            let revoked = sandbox.token.clone().map(|token| (token, sandbox.expires_at));
            let container = sandbox.container.clone();
            store.state.revoked.extend(revoked);
            save(&mut store)?;
            container
        };
        self.finish_deletion(name, container).await
    }

    /// Removes the container of a `Deleting` sandbox, then forgets it; on
    /// failure, the entry stays for the reaper to retry.
    async fn finish_deletion(&self, name: &str, container: Option<String>) -> Result<(), Failure> {
        if let Some(container) = container {
            let removal = tokio::time::timeout(REMOVE_TIMEOUT, docker::remove(&self.docker, &container)).await;
            if !matches!(removal, Ok(Ok(()))) {
                tracing::warn!(%name, "cannot remove the container yet");
                return Err(Failure::Unavailable);
            }
        }
        let mut store = self.store.lock().await;
        store.state.sandboxes.remove(name);
        save(&mut store)?;
        tracing::info!(%name, "sandbox deleted");
        Ok(())
    }

    /// Removes expired sandboxes, retries pending deletions, removes this
    /// instance's containers the state does not know, and forgets
    /// sandboxes whose container vanished.
    pub async fn reap(&self) {
        let now = now();
        let pending = {
            let mut store = self.store.lock().await;
            for sandbox in store.state.sandboxes.values_mut() {
                if sandbox.status == Status::Active && sandbox.expires_at <= now {
                    sandbox.status = Status::Deleting;
                }
            }
            // Saved on every pass, even unchanged: this also republishes the
            // revocation list if a previous write of it failed.
            if save(&mut store).is_err() {
                return;
            }
            store
                .state
                .sandboxes
                .iter()
                .filter(|(_, sandbox)| sandbox.status == Status::Deleting)
                .map(|(name, sandbox)| (name.clone(), sandbox.container.clone()))
                .collect::<Vec<_>>()
        };
        for (name, container) in pending {
            let _ = self.finish_deletion(&name, container).await;
        }
        self.reap_strays().await;
    }

    /// Reconciles Docker with the state, outside `Creating` sandboxes: stray
    /// containers are removed, sandboxes whose container vanished deleted.
    async fn reap_strays(&self) {
        let instance = self.store.lock().await.state.instance.clone();
        let Ok(containers) = docker::list(&self.docker, &self.settings.label, &instance).await else {
            return;
        };
        let (strays, missing) = {
            let store = self.store.lock().await;
            let sandboxes = &store.state.sandboxes;
            let known = |id: &str| sandboxes.values().any(|s| s.container.as_deref() == Some(id));
            let creating = |name: &str| sandboxes.get(name).is_some_and(|s| s.status == Status::Creating);
            let strays: Vec<String> = containers
                .iter()
                .filter(|(id, name)| !known(id) && !creating(name))
                .map(|(id, _)| id.clone())
                .collect();
            // Absent from a listing that may predate them: checked again below.
            let listed = |id: &String| containers.iter().any(|(c, _)| c == id);
            let missing: Vec<(String, String)> = sandboxes
                .iter()
                .filter(|(_, s)| s.status == Status::Active)
                .filter_map(|(name, s)| Some((name.clone(), s.container.clone()?)))
                .filter(|(_, id)| !listed(id))
                .collect();
            (strays, missing)
        };
        for id in strays {
            tracing::warn!(container = %id, "removing a stray container");
            let _ = docker::remove(&self.docker, &id).await;
        }
        for (name, id) in missing {
            if docker::exists(&self.docker, &id).await != Ok(false) {
                continue;
            }
            let mut store = self.store.lock().await;
            if let Some(sandbox) = store.state.sandboxes.get_mut(&name)
                && sandbox.status == Status::Active
                && sandbox.container.as_deref() == Some(id.as_str())
            {
                tracing::warn!(%name, "the container vanished");
                sandbox.status = Status::Deleting;
                let _ = save(&mut store);
            }
        }
    }

    /// The sandboxes, without their tokens.
    pub async fn list(&self) -> Vec<(String, Sandbox)> {
        let store = self.store.lock().await;
        store
            .state
            .sandboxes
            .iter()
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect()
    }

    fn ttl(&self, requested: Option<u64>) -> Result<u64, Failure> {
        let max = self.settings.lifetime;
        match requested {
            None => Ok(max),
            Some(ttl) if (60..=max).contains(&ttl) => Ok(ttl),
            Some(_) => Err(Failure::Ttl(max)),
        }
    }

    /// A token for sandbox `name`, from `client` only, through the bastion
    /// only, allowing up to `expires_at - 1` included.
    fn token(&self, name: &str, client: IpAddr, expires_at: u64) -> Result<Token, Failure> {
        let internal = |e: biscuit_ssh_core::Error| {
            tracing::error!(error = %e, "cannot mint a token");
            Failure::Unavailable
        };
        let right = Right {
            server: name.parse().map_err(internal)?,
            user: self.settings.account.clone(),
        };
        let restrictions = [
            Restriction::ExpiresAt(UNIX_EPOCH + Duration::from_secs(expires_at - 1)),
            Restriction::SourceNetworks(vec![Network::host(client)]),
            Restriction::Mode(Mode::Bastion),
        ];
        let token = mint(&self.settings.signing_key, &[right], &restrictions).map_err(internal)?;
        let id = inspect(&token)
            .map_err(internal)?
            .into_iter()
            .next()
            .ok_or(Failure::Unavailable)?
            .revocation_id;
        Ok(Token { token, id })
    }
}

struct Token {
    token: String,
    id: String,
}

fn save(store: &mut Store) -> Result<(), Failure> {
    store.save(now()).map_err(|e| {
        tracing::error!(error = %e, "cannot save the state");
        Failure::Unavailable
    })
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// 128 random bits, in hex.
pub fn random_hex() -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("no system random source: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
