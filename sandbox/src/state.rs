//! Persistent state: the single source of truth for sandboxes and revoked
//! tokens.
//!
//! Every change is written to disk before any effect outside the service
//! (Docker, the revocation list) relies on it, so a crash at any point is
//! recovered from on the next start. The revocation list read by the
//! bastion is a projection of this state, rewritten after each change.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// Where a sandbox is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Reserved; its container may exist without being recorded yet.
    Creating,
    /// Running, with a valid token.
    Active,
    /// Its container is being removed.
    Deleting,
}

/// A sandbox, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sandbox {
    /// See [`Status`].
    pub status: Status,
    /// Canonical image reference requested.
    pub image: String,
    /// Immutable ID of the container, once created.
    pub container: Option<String>,
    /// ID of the image the container runs.
    pub image_id: Option<String>,
    /// Revocation identifier of its current token, once issued.
    pub token: Option<String>,
    /// First second, since the Unix epoch, the token no longer allows.
    pub expires_at: u64,
    /// Address of the client that created or last renewed it.
    pub client: IpAddr,
}

/// The whole state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Identifies the containers of this instance, through their label.
    pub instance: String,
    /// Sandboxes, by name.
    pub sandboxes: BTreeMap<String, Sandbox>,
    /// Revoked token identifiers, with the first second their token no
    /// longer allows: they are dropped once expired anyway.
    pub revoked: BTreeMap<String, u64>,
}

/// The state on disk, owned by this process alone.
pub struct Store {
    path: PathBuf,
    revocation_list: PathBuf,
    /// Held for the life of the process: one instance at a time.
    _lock: File,
    /// Current state, as last written.
    pub state: State,
}

impl Store {
    /// Opens the state in `dir`, taking its lock, or creates it with a new
    /// instance identifier.
    pub fn open(dir: &Path, revocation_list: &Path, new_instance: impl FnOnce() -> String) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let lock = File::create(dir.join("lock"))?;
        if lock.try_lock().is_err() {
            bail!("another instance uses {}", dir.display());
        }
        let path = dir.join("state.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("invalid {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State {
                instance: new_instance(),
                ..State::default()
            },
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let mut store = Self {
            path,
            revocation_list: revocation_list.to_owned(),
            _lock: lock,
            state,
        };
        store.save(0)?;
        Ok(store)
    }

    /// Writes the state, then the revocation list without the tokens expired
    /// by `now`, each atomically.
    pub fn save(&mut self, now: u64) -> anyhow::Result<()> {
        self.state.revoked.retain(|_, expires_at| *expires_at > now);
        write_atomically(&self.path, &serde_json::to_vec_pretty(&self.state)?)?;
        let mut list = String::from("# Written by biscuit-ssh-sandbox: do not edit.\n");
        for id in self.state.revoked.keys() {
            list.push_str(id);
            list.push('\n');
        }
        write_atomically(&self.revocation_list, list.as_bytes())
    }
}

/// Replaces `path` with `content`, durably: readers see the old file or
/// the new one, never a mix, even after a crash.
fn write_atomically(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().context("path without a directory")?;
    let temporary = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut file = File::create(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(dir)?.sync_all()
    };
    write().with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("biscuit-ssh-sandbox-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn persists_state_and_projects_revocations() {
        let dir = temporary_dir("state");
        let list = dir.join("revoked");
        let mut store = Store::open(&dir, &list, || "instance-1".to_owned()).unwrap();
        store.state.revoked.insert("aa".repeat(64), 100);
        store.state.revoked.insert("bb".repeat(64), 200);
        store.state.sandboxes.insert(
            "sb-1".to_owned(),
            Sandbox {
                status: Status::Active,
                image: "docker.io/library/alpine:latest".to_owned(),
                container: Some("c1".to_owned()),
                image_id: None,
                token: Some("cc".repeat(64)),
                expires_at: 300,
                client: "192.0.2.7".parse().unwrap(),
            },
        );
        // The token expiring at 100 no longer needs revoking at 100.
        store.save(100).unwrap();
        let written = std::fs::read_to_string(&list).unwrap();
        assert!(!written.contains(&"aa".repeat(64)) && written.contains(&"bb".repeat(64)));
        assert!(biscuit_ssh_core::RevocationList::parse(&written).is_ok());
        let state = store.state.clone();
        drop(store);

        let reopened = Store::open(&dir, &list, || unreachable!()).unwrap();
        assert_eq!(reopened.state, state);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn allows_one_instance_at_a_time() {
        let dir = temporary_dir("lock");
        let list = dir.join("revoked");
        let first = Store::open(&dir, &list, || "i".to_owned()).unwrap();
        assert!(Store::open(&dir, &list, || "i".to_owned()).is_err());
        drop(first);
        assert!(Store::open(&dir, &list, || "i".to_owned()).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
