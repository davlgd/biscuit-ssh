//! The SSH server side: authenticating clients and relaying their sessions.
//!
//! Clients log in as `user@server`, where `server` names a configured
//! target. Authentication takes two steps: a public key (its fingerprint is
//! the `public_key` fact), then the token through keyboard-interactive,
//! answering the [`BASTION_TOKEN_PROMPT`] prompt.
//!
//! Only session channels are relayed (shell, exec, subsystems such as sftp,
//! with terminal and signal handling). Port, agent and X11 forwarding,
//! environment variables and every other channel type are refused.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow};
use biscuit_ssh_core::api::BASTION_TOKEN_PROMPT;
use biscuit_ssh_core::{AccessRequest, Mode, Name};
use bytes::Bytes;
use russh::keys::{HashAlg, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty, Sig};
use tokio::sync::{Semaphore, oneshot, watch};
use tracing::Instrument;

use crate::access::{self, Cutter, Grant, until_cut};
use crate::config::Settings;
use crate::relay::{self, Relay, Replies};
use crate::target::{self, TargetConnection};

/// How long a forwarded request may wait for the target's answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// One client connection.
pub struct Connection {
    settings: Arc<Settings>,
    /// Bounds concurrent token checks for new logins, which are CPU-bound:
    /// beyond it, logins are refused so lease renewals are never starved.
    admission: Arc<Semaphore>,
    peer: IpAddr,
    span: tracing::Span,
    /// Login name and fingerprint of the key the client proved it holds.
    verified_key: Option<(String, String)>,
    /// Set once the token is accepted, with the end of the first lease.
    grant: Option<(Arc<Grant>, u64)>,
    cutter: Arc<Cutter>,
    /// Becomes true when the connection is cut.
    cut: watch::Receiver<bool>,
    target: Option<TargetConnection>,
    relays: HashMap<ChannelId, Relay>,
}

/// A request forwarded to the target, which answers it.
enum Request<'a> {
    Pty {
        term: &'a str,
        size: (u32, u32, u32, u32),
        modes: &'a [(Pty, u32)],
    },
    Shell,
    Exec(&'a [u8]),
    Subsystem(&'a str),
}

impl Connection {
    /// A new connection from `peer`; `cutter` closes its socket when cut.
    pub fn new(settings: Arc<Settings>, admission: Arc<Semaphore>, peer: IpAddr, cutter: Arc<Cutter>) -> Self {
        let peer = peer.to_canonical();
        Self {
            settings,
            admission,
            peer,
            span: tracing::info_span!("client", %peer, server = tracing::field::Empty),
            verified_key: None,
            grant: None,
            cut: cutter.watch(),
            cutter,
            target: None,
            relays: HashMap::new(),
        }
    }

    /// Checks the token presented by the client for `login`.
    async fn authenticate(&mut self, login: &str, fingerprint: String, token: String) -> anyhow::Result<()> {
        let (user, server) = login.rsplit_once('@').context("the login must be user@server")?;
        let (user, server): (Name, Name) = (user.parse()?, server.parse()?);
        let target = self
            .settings
            .targets
            .get(&server)
            .with_context(|| format!("unknown server {server}"))?
            .clone();
        let request = AccessRequest {
            time: SystemTime::now(),
            source_ip: self.peer,
            server,
            user,
            command: None,
            public_key: fingerprint,
            mode: Mode::Bastion,
        };
        let grant = Arc::new(Grant { token, request, target });

        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| anyhow!("busy"))?;
        let (settings, checked) = (Arc::clone(&self.settings), Arc::clone(&grant));
        let authorization = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            access::authorize(&settings, &checked.token, &checked.request, settings.check_interval)
        })
        .await?
        .map_err(|refusal| anyhow!("token refused: {}", refusal.kind()))?;

        self.span.record("server", grant.request.server.as_str());
        tracing::info!(
            parent: &self.span,
            user = %grant.request.user,
            key = %grant.request.public_key,
            token = authorization.token_id(),
            "authenticated"
        );
        self.grant = Some((grant, authorization.valid_until()));
        Ok(())
    }

    /// Opens the target side of a new session channel, connecting to the
    /// target on first use.
    async fn open_relay(&mut self, id: ChannelId, client: russh::server::Handle) -> anyhow::Result<()> {
        if self.target.is_none() {
            let (grant, _) = self.grant.as_ref().context("not authenticated")?;
            let permit = Arc::clone(&self.admission).acquire_owned().await?;
            let connection =
                target::connect(Arc::clone(&self.settings), Arc::clone(grant), permit, &self.cutter).await?;
            self.target = Some(connection);
        }
        let target = self.target.as_ref().context("no target connection")?;
        let (from_target, to_target) = target.channel_open_session().await?.split();
        let to_target = Arc::new(to_target);
        self.cutter.watch_session(&to_target);
        let replies = Replies::default();
        let pump = relay::pump(from_target, client, id, replies.clone(), self.cutter.watch());
        tokio::spawn(pump.instrument(self.span.clone()));
        self.relays.insert(id, Relay { to_target, replies });
        Ok(())
    }

    fn relay(&self, id: ChannelId) -> anyhow::Result<&Relay> {
        self.relays.get(&id).context("unknown channel")
    }

    /// Forwards `request` to the target; the receiver gets its answer.
    async fn forward(&self, id: ChannelId, request: Request<'_>) -> anyhow::Result<oneshot::Receiver<bool>> {
        until_cut(self.cut.clone(), async {
            let relay = self.relay(id)?;
            let reply = relay.replies.expect();
            let to_target = &relay.to_target;
            match request {
                Request::Pty { term, size, modes } => {
                    let (columns, rows, width, height) = size;
                    to_target
                        .request_pty(true, term, columns, rows, width, height, modes)
                        .await
                }
                Request::Shell => to_target.request_shell(true).await,
                Request::Exec(command) => to_target.exec(true, command).await,
                Request::Subsystem(name) => to_target.request_subsystem(true, name).await,
            }?;
            Ok(reply)
        })
        .await
    }

    /// Waits for the target's answer to a forwarded request and relays it.
    async fn answer(&self, id: ChannelId, reply: oneshot::Receiver<bool>, session: &mut Session) -> anyhow::Result<()> {
        let answer = until_cut(self.cut.clone(), async {
            Ok(tokio::time::timeout(REPLY_TIMEOUT, reply).await)
        })
        .await?;
        if matches!(answer, Ok(Ok(true))) {
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }
}

impl Drop for Connection {
    /// Closes the target connection with the client's: sessions must not
    /// outlive the connection that was authorized (and possibly cut).
    ///
    /// Commands started without a terminal would survive a mere disconnect
    /// (sshd only hangs up terminals), so each session is sent `HUP` first.
    /// Processes that detach themselves (`nohup`, `setsid`) still survive.
    fn drop(&mut self) {
        let relays: Vec<Relay> = self.relays.drain().map(|(_, relay)| relay).collect();
        if let Some(target) = self.target.take() {
            tokio::spawn(async move {
                for relay in relays {
                    let _ = relay.to_target.signal(Sig::HUP).await;
                }
                let _ = target.disconnect(russh::Disconnect::ByApplication, "", "").await;
            });
        }
    }
}

impl russh::server::Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_publickey(&mut self, login: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // Called once the client proved it holds the key.
        self.verified_key = Some((login.to_owned(), key.fingerprint(HashAlg::Sha256).to_string()));
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
            partial_success: true,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        login: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        // The token only counts after a verified key, for the same login.
        let Some(fingerprint) = self
            .verified_key
            .as_ref()
            .filter(|(key_login, _)| key_login == login)
            .map(|(_, fingerprint)| fingerprint.clone())
        else {
            return Ok(Auth::reject());
        };
        let Some(mut response) = response else {
            return Ok(Auth::Partial {
                name: Cow::Borrowed(""),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(vec![(Cow::Borrowed(BASTION_TOKEN_PROMPT), false)]),
            });
        };
        let token = response
            .next()
            .map(|t| String::from_utf8_lossy(&t).into_owned())
            .unwrap_or_default();
        match self.authenticate(login, fingerprint, token).await {
            Ok(()) => Ok(Auth::Accept),
            Err(error) => {
                tracing::warn!(parent: &self.span, error = %error, "authentication refused");
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let (grant, lease_end) = self.grant.as_ref().context("no grant")?;
        let guard = access::guard(
            Arc::clone(&self.settings),
            Arc::clone(grant),
            *lease_end,
            session.handle(),
            Arc::clone(&self.cutter),
        );
        tokio::spawn(guard.instrument(self.span.clone()));
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Requests are handled through the callbacks below, not the channel.
        let id = channel.id();
        drop(channel);
        let client = session.handle();
        let cut = self.cut.clone();
        match until_cut(cut, self.open_relay(id, client)).await {
            Ok(()) => reply.accept().await,
            Err(error) => {
                tracing::warn!(parent: &self.span, error = %error, "cannot reach the target");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = (col_width, row_height, pix_width, pix_height);
        let reply = self.forward(id, Request::Pty { term, size, modes }).await?;
        self.answer(id, reply, session).await
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, "shell");
        let reply = self.forward(id, Request::Shell).await?;
        self.answer(id, reply, session).await
    }

    async fn exec_request(&mut self, id: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, command = %String::from_utf8_lossy(command), "exec");
        let reply = self.forward(id, Request::Exec(command)).await?;
        self.answer(id, reply, session).await
    }

    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, subsystem = name, "subsystem");
        let reply = self.forward(id, Request::Subsystem(name)).await?;
        self.answer(id, reply, session).await
    }

    async fn env_request(&mut self, id: ChannelId, _: &str, _: &str, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        id: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        until_cut(self.cut.clone(), async {
            let to_target = &self.relay(id)?.to_target;
            Ok(to_target
                .window_change(col_width, row_height, pix_width, pix_height)
                .await?)
        })
        .await
    }

    async fn signal(&mut self, id: ChannelId, signal: Sig, _: &mut Session) -> Result<(), Self::Error> {
        until_cut(self.cut.clone(), async {
            Ok(self.relay(id)?.to_target.signal(signal).await?)
        })
        .await
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        until_cut(self.cut.clone(), async {
            let to_target = &self.relay(id)?.to_target;
            Ok(to_target.data_bytes(Bytes::copy_from_slice(data)).await?)
        })
        .await
    }

    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        until_cut(self.cut.clone(), async {
            if let Some(relay) = self.relays.get(&id) {
                relay.to_target.eof().await?;
            }
            Ok(())
        })
        .await
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(relay) = self.relays.remove(&id) {
            let _ = until_cut(self.cut.clone(), async { Ok(relay.to_target.close().await?) }).await;
        }
        Ok(())
    }
}
