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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use biscuit_ssh_core::api::BASTION_TOKEN_PROMPT;
use biscuit_ssh_core::{AccessRequest, Mode, Name};
use bytes::Bytes;
use russh::keys::{HashAlg, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty, Sig};
use tokio::sync::watch;
use tracing::Instrument;

use crate::access::{self, Grant};
use crate::config::Settings;
use crate::relay::{self, Relay, Replies};
use crate::target::{self, TargetConnection};

/// How long a forwarded request may wait for the target's answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Creates one [`Connection`] per client.
pub struct Bastion {
    /// Shared by every connection.
    pub settings: Arc<Settings>,
}

impl russh::server::Server for Bastion {
    type Handler = Connection;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Connection {
        let (cut_sender, cut) = watch::channel(false);
        Connection {
            settings: Arc::clone(&self.settings),
            peer: peer.map(|p| p.ip().to_canonical()),
            span: tracing::info_span!(
                "client",
                peer = %peer.map_or_else(|| "unknown".to_owned(), |p| p.ip().to_canonical().to_string()),
                server = tracing::field::Empty,
            ),
            verified_key: None,
            grant: None,
            cut_sender: Some(cut_sender),
            pending_lease: None,
            cut,
            target: None,
            relays: HashMap::new(),
        }
    }

    fn handle_session_error(&mut self, error: anyhow::Error) {
        tracing::debug!(error = %error, "connection ended with an error");
    }
}

/// One client connection.
pub struct Connection {
    settings: Arc<Settings>,
    peer: Option<IpAddr>,
    span: tracing::Span,
    /// Login name and fingerprint of the key the client proved it holds.
    verified_key: Option<(String, String)>,
    /// Set once the token is accepted.
    grant: Option<Arc<Grant>>,
    /// Handed to the lease guard once authenticated.
    cut_sender: Option<watch::Sender<bool>>,
    /// End of the first lease and the cut switch, for the lease guard.
    pending_lease: Option<(u64, watch::Sender<bool>)>,
    /// Becomes true when the lease guard cuts the connection.
    cut: watch::Receiver<bool>,
    target: Option<TargetConnection>,
    relays: HashMap<ChannelId, Relay>,
}

impl Connection {
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
            source_ip: self.peer.context("unknown client address")?,
            server,
            user,
            command: None,
            public_key: fingerprint,
            mode: Mode::Bastion,
        };
        let grant = Arc::new(Grant { token, request, target });

        let (settings, checked) = (Arc::clone(&self.settings), Arc::clone(&grant));
        let authorization = tokio::task::spawn_blocking(move || {
            let lifetime = settings.check_interval;
            access::authorize(&settings, &checked.token, &checked.request, lifetime)
        })
        .await?
        .map_err(|refusal| anyhow!("token refused: {}", refusal.kind()))?;

        self.span.record("server", grant.request.server.as_str());
        tracing::info!(
            parent: &self.span,
            user = %grant.request.user,
            server = %grant.request.server,
            key = %grant.request.public_key,
            token = authorization.token_id(),
            "authenticated"
        );
        let cut = self.cut_sender.take().context("already authenticated")?;
        self.grant = Some(grant);
        self.pending_lease = Some((authorization.valid_until(), cut));
        Ok(())
    }

    /// The target connection, opened on first use.
    async fn target(&mut self) -> anyhow::Result<&TargetConnection> {
        if self.target.is_none() {
            let grant = Arc::clone(self.grant.as_ref().context("not authenticated")?);
            let connection = target::connect(Arc::clone(&self.settings), grant).await?;
            self.target = Some(connection);
        }
        self.target.as_ref().context("no target connection")
    }

    /// Opens the target side of a new session channel.
    async fn open_relay(&mut self, id: ChannelId, client: russh::server::Handle) -> anyhow::Result<()> {
        let channel = self.target().await?.channel_open_session().await?;
        let (from_target, to_target) = channel.split();
        let replies = Replies::default();
        let pump = relay::pump(from_target, client, id, replies.clone());
        tokio::spawn(pump.instrument(self.span.clone()));
        self.relays.insert(id, Relay { to_target, replies });
        Ok(())
    }

    fn relay(&self, id: ChannelId) -> anyhow::Result<&Relay> {
        self.relays.get(&id).context("unknown channel")
    }

    /// Fails once the lease guard has cut the connection.
    fn check_not_cut(&self) -> anyhow::Result<()> {
        if *self.cut.borrow() {
            bail!("connection cut");
        }
        Ok(())
    }

    /// Waits for the target's answer to a forwarded request and relays it,
    /// unless the connection is cut first.
    async fn answer(
        &mut self,
        id: ChannelId,
        reply: tokio::sync::oneshot::Receiver<bool>,
        session: &mut Session,
    ) -> anyhow::Result<()> {
        let mut cut = self.cut.clone();
        let accepted = tokio::select! {
            answer = tokio::time::timeout(REPLY_TIMEOUT, reply) => matches!(answer, Ok(Ok(true))),
            _ = cut.wait_for(|cut| *cut) => bail!("connection cut"),
        };
        if accepted {
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    /// Sends data to the target, unless the connection is cut first.
    async fn forward_data(&self, id: ChannelId, data: &[u8]) -> anyhow::Result<()> {
        let mut cut = self.cut.clone();
        tokio::select! {
            sent = self.relay(id)?.to_target.data_bytes(Bytes::copy_from_slice(data)) => Ok(sent?),
            _ = cut.wait_for(|cut| *cut) => bail!("connection cut"),
        }
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
        let grant = Arc::clone(self.grant.as_ref().context("no grant")?);
        let (lease_end, cut) = self.pending_lease.take().context("no lease")?;
        let guard = access::guard(Arc::clone(&self.settings), grant, lease_end, session.handle(), cut);
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
        self.check_not_cut()?;
        match self.open_relay(id, session.handle()).await {
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
        self.check_not_cut()?;
        let relay = self.relay(id)?;
        let reply = relay.replies.expect();
        relay
            .to_target
            .request_pty(true, term, col_width, row_height, pix_width, pix_height, modes)
            .await?;
        self.answer(id, reply, session).await
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.check_not_cut()?;
        tracing::info!(parent: &self.span, "shell");
        let relay = self.relay(id)?;
        let reply = relay.replies.expect();
        relay.to_target.request_shell(true).await?;
        self.answer(id, reply, session).await
    }

    async fn exec_request(&mut self, id: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        self.check_not_cut()?;
        tracing::info!(parent: &self.span, command = %String::from_utf8_lossy(command), "exec");
        let relay = self.relay(id)?;
        let reply = relay.replies.expect();
        relay.to_target.exec(true, command).await?;
        self.answer(id, reply, session).await
    }

    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        self.check_not_cut()?;
        tracing::info!(parent: &self.span, subsystem = name, "subsystem");
        let relay = self.relay(id)?;
        let reply = relay.replies.expect();
        relay.to_target.request_subsystem(true, name).await?;
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
        self.check_not_cut()?;
        let relay = self.relay(id)?;
        relay
            .to_target
            .window_change(col_width, row_height, pix_width, pix_height)
            .await?;
        Ok(())
    }

    async fn signal(&mut self, id: ChannelId, signal: Sig, _: &mut Session) -> Result<(), Self::Error> {
        self.check_not_cut()?;
        self.relay(id)?.to_target.signal(signal).await?;
        Ok(())
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        self.check_not_cut()?;
        self.forward_data(id, data).await
    }

    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(relay) = self.relays.get(&id) {
            relay.to_target.eof().await?;
        }
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(relay) = self.relays.remove(&id) {
            let _ = relay.to_target.close().await;
        }
        Ok(())
    }
}
