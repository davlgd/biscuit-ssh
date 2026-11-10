//! The SSH server side: authenticating clients and relaying their sessions.
//!
//! Clients log in as `user@server`, where `server` names a configured
//! target. Authentication takes two steps: a public key (its fingerprint is
//! the `public_key` fact), then the token through keyboard-interactive, in
//! parts (see [`bastion_login`]). When the token alone doesn't allow the
//! login, the bastion asks for a command, which it checks with the token
//! and forces on every session of the connection, as `sshd` does with
//! `force-command`: through the certificate it logs in to servers with, and
//! by running it in containers whatever the client asks.
//!
//! Only session channels are relayed (shell, exec, subsystems such as sftp,
//! with terminal and signal handling), to a server over SSH or into a
//! container (see [`container`]). Port, agent and X11 forwarding,
//! environment variables and every other channel type are refused.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use biscuit_ssh_core::bastion_login::{self, Assembly, Progress};
use biscuit_ssh_core::{AccessRequest, Command, Mode, Name};
use bytes::Bytes;
use russh::keys::HashAlg;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty, Sig};
use tokio::sync::{Semaphore, oneshot, watch};
use tracing::Instrument;

use crate::access::{self, Cutter, Grant, until_cut};
use crate::access::{Kind, Target};
use crate::config::Settings;
use crate::container::{self, ContainerChannel, Output};
use crate::relay::{self, Relay, Replies};
use crate::target::{self, TargetConnection};

/// Asks for one part of the token.
fn ask_token_part(part: usize) -> Auth {
    Auth::Partial {
        name: Cow::Borrowed(""),
        instructions: Cow::Borrowed(""),
        prompts: Cow::Owned(vec![(Cow::Owned(bastion_login::prompt(part)), false)]),
    }
}

/// Asks for the command to force, see [`bastion_login::COMMAND_PROMPT`].
fn ask_command() -> Auth {
    Auth::Partial {
        name: Cow::Borrowed(""),
        instructions: Cow::Borrowed(""),
        prompts: Cow::Owned(vec![(Cow::Borrowed(bastion_login::COMMAND_PROMPT), true)]),
    }
}

/// The target side of a session channel.
enum SessionChannel {
    /// Relayed to a server's SSH channel.
    Ssh(Relay),
    /// Run in a container.
    Container(ContainerChannel),
}

/// How long a forwarded request may wait for the target's answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a login was refused: `kind` is told to the client, `detail` logged.
struct Refused {
    kind: &'static str,
    detail: anyhow::Error,
}

impl Refused {
    fn new(kind: &'static str, detail: anyhow::Error) -> Self {
        Self { kind, detail }
    }

    /// What the client is told: the kind of refusal and what it usually
    /// means, never token content or configuration details.
    fn explanation(&self, peer: IpAddr) -> String {
        let meaning = match self.kind {
            "invalid_login" => "log in as user@server, with the server named as in the token",
            "invalid_command" => "the command must be a single printable line of at most 1024 bytes",
            "denied" => "the token does not allow this login (server, account, command, restrictions or expiry)",
            "revoked" => "the token has been revoked",
            "invalid_token" => "the token is malformed or not issued for this bastion",
            "busy" => "the bastion is busy, retry later",
            _ => "internal error",
        };
        format!(
            "biscuit-ssh bastion: access refused ({}) for {peer}: {meaning}",
            self.kind
        )
    }
}

/// A token refused without a command, waiting for the client's command.
struct AwaitingCommand {
    login: String,
    fingerprint: String,
    token: String,
}

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
    /// The token received so far.
    token_parts: Assembly,
    /// The token, when it was refused without a command and the client was
    /// asked for one, with the login and key fingerprint it came with.
    awaiting_command: Option<AwaitingCommand>,
    /// Set when the token was refused: the client has been told why, and
    /// the connection ends on its next answer.
    refused: bool,
    /// Set once the token is accepted, with the end of the first lease.
    grant: Option<(Arc<Grant>, u64)>,
    cutter: Arc<Cutter>,
    /// Becomes true when the connection is cut.
    cut: watch::Receiver<bool>,
    /// The SSH connection to a server target, opened on first use.
    target: Option<TargetConnection>,
    channels: HashMap<ChannelId, SessionChannel>,
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
            token_parts: Assembly::default(),
            awaiting_command: None,
            refused: false,
            grant: None,
            cut: cutter.watch(),
            cutter,
            target: None,
            channels: HashMap::new(),
        }
    }

    /// Checks the token presented by the client for `login`, with the
    /// command to force if any.
    async fn authenticate(
        &mut self,
        login: &str,
        fingerprint: String,
        token: String,
        command: Option<Command>,
    ) -> Result<(), Refused> {
        let (user, server) = login
            .rsplit_once('@')
            .and_then(|(user, server)| Some((user.parse::<Name>().ok()?, server.parse::<Name>().ok()?)))
            .ok_or(Refused::new("invalid_login", anyhow!("invalid login")))?;
        // Unknown names are reported as mere denials, so clients cannot
        // enumerate targets.
        let unknown = || Refused::new("denied", anyhow!("unknown server {server}"));
        let kind = match (self.settings.servers.contains_key(&server), &self.settings.containers) {
            (true, _) => Kind::Server,
            (false, Some(_)) => Kind::Container,
            (false, None) => return Err(unknown()),
        };
        let request = AccessRequest {
            time: SystemTime::now(),
            source_ip: self.peer,
            server: server.clone(),
            user,
            command,
            public_key: fingerprint,
            mode: Mode::Bastion,
        };

        // The token is checked before any Docker request: invalid tokens
        // cost no more than for servers.
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| Refused::new("busy", anyhow!("too many logins")))?;
        let (settings, checked) = (Arc::clone(&self.settings), (token.clone(), request.clone()));
        let authorization = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (token, request) = checked;
            access::authorize(&settings, kind, &token, &request, settings.check_interval)
        })
        .await
        .map_err(|e| Refused::new("internal", e.into()))?
        .map_err(|refusal| match (kind, refusal.kind()) {
            // A name that is no server is checked as a container: a token for
            // servers then fails there, and must look like any unknown name.
            (Kind::Container, "invalid_token") => unknown(),
            // A timeout depends on the load: the client may retry.
            (_, "overloaded") => Refused::new("busy", anyhow!("token evaluation timed out")),
            (_, kind) => Refused::new(kind, anyhow!("token refused")),
        })?;

        let target = match kind {
            Kind::Server => Target::Server(self.settings.servers.get(&server).ok_or_else(unknown)?.clone()),
            Kind::Container => {
                let containers = self.settings.containers.as_ref().ok_or_else(unknown)?;
                match container::find(containers, &server).await {
                    Ok(Some(id)) => Target::Container(id),
                    Ok(None) => return Err(unknown()),
                    Err(e) => return Err(Refused::new("internal", e)),
                }
            }
        };
        let grant = Arc::new(Grant { token, request, target });
        self.span.record("server", grant.request.server.as_str());
        tracing::info!(
            parent: &self.span,
            user = %grant.request.user,
            key = %grant.request.public_key,
            token = authorization.token_id(),
            command = grant.request.command.as_ref().map(Command::as_str),
            "authenticated"
        );
        self.grant = Some((grant, authorization.valid_until()));
        Ok(())
    }

    /// Logs a refused login and tells the client why. SSH has no refusal
    /// message: an extra round without prompts shows the reason, and the
    /// connection ends on the client's answer.
    fn refuse(&mut self, refused: Refused) -> Auth {
        tracing::warn!(parent: &self.span, kind = refused.kind, error = %refused.detail, "authentication refused");
        self.refused = true;
        Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Owned(refused.explanation(self.peer)),
            prompts: Cow::Owned(Vec::new()),
        }
    }

    /// Opens the target side of a new session channel, connecting to a
    /// server target on first use.
    async fn open_channel(&mut self, id: ChannelId, client: russh::server::Handle) -> anyhow::Result<()> {
        let (grant, _) = self.grant.as_ref().context("not authenticated")?;
        let server = match &grant.target {
            Target::Server(server) => server.clone(),
            Target::Container(_) => {
                self.channels
                    .insert(id, SessionChannel::Container(ContainerChannel::default()));
                return Ok(());
            }
        };
        if self.target.is_none() {
            let grant = Arc::clone(grant);
            let permit = Arc::clone(&self.admission).acquire_owned().await?;
            let connection = target::connect(Arc::clone(&self.settings), grant, &server, permit, &self.cutter).await?;
            self.target = Some(connection);
        }
        let target = self.target.as_ref().context("no target connection")?;
        let (from_target, to_target) = target.channel_open_session().await?.split();
        let to_target = Arc::new(to_target);
        self.cutter.watch_session(&to_target);
        let replies = Replies::default();
        let pump = relay::pump(from_target, client, id, replies.clone(), self.cutter.watch());
        tokio::spawn(pump.instrument(self.span.clone()));
        self.channels
            .insert(id, SessionChannel::Ssh(Relay { to_target, replies }));
        Ok(())
    }

    fn relay(&self, id: ChannelId) -> anyhow::Result<&Relay> {
        match self.channels.get(&id) {
            Some(SessionChannel::Ssh(relay)) => Ok(relay),
            _ => bail!("unknown channel"),
        }
    }

    /// The container session of channel `id`, if it is one.
    fn container_channel(&mut self, id: ChannelId) -> Option<&mut ContainerChannel> {
        match self.channels.get_mut(&id) {
            Some(SessionChannel::Container(channel)) => Some(channel),
            _ => None,
        }
    }

    /// Starts `command`, or a shell, in the container of channel `id`, and
    /// tells the client whether it started.
    async fn start_in_container(
        &mut self,
        id: ChannelId,
        command: Option<&[u8]>,
        session: &mut Session,
    ) -> anyhow::Result<()> {
        let output = Output {
            client: session.handle(),
            channel: id,
            cut: self.cut.clone(),
        };
        let (grant, _) = self.grant.as_ref().context("not authenticated")?;
        let (Target::Container(container), Some(containers)) = (&grant.target, &self.settings.containers) else {
            bail!("not a container session");
        };
        let (container, user, docker) = (container.clone(), grant.request.user.clone(), containers.docker.clone());
        // A forced command replaces whatever the client asked, as with sshd.
        let forced = grant.request.command.as_ref().map(|c| c.as_str().as_bytes().to_vec());
        let command = forced.as_deref().or(command);
        let channel = self.container_channel(id).context("unknown channel")?;
        let cut = output.cut.clone();
        let started = until_cut(cut, channel.start(&docker, &container, user.as_str(), command, output)).await;
        match started {
            Ok(()) => session.channel_success(id)?,
            Err(error) => {
                tracing::warn!(parent: &self.span, error = %error, "cannot start the command");
                session.channel_failure(id)?;
            }
        }
        Ok(())
    }

    /// The Docker client, for container sessions.
    fn docker(&self) -> anyhow::Result<bollard::Docker> {
        let containers = self.settings.containers.as_ref().context("containers are disabled")?;
        Ok(containers.docker.clone())
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
        let relays: Vec<Relay> = self
            .channels
            .drain()
            .filter_map(|(_, channel)| match channel {
                SessionChannel::Ssh(relay) => Some(relay),
                SessionChannel::Container(_) => None,
            })
            .collect();
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

    async fn auth_publickey(&mut self, login: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        // Called once the client proved it holds the key.
        let fingerprint = key.public_key.fingerprint(HashAlg::Sha256).to_string();
        self.verified_key = Some((login.to_owned(), fingerprint));
        self.awaiting_command = None;
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
        if self.refused {
            // Told why on the previous round: end the connection rather than
            // let the client try again and again.
            bail!("login refused");
        }
        let Some(mut response) = response else {
            self.token_parts = Assembly::default();
            self.awaiting_command = None;
            return Ok(ask_token_part(1));
        };
        let answer = response.next().unwrap_or_default();
        if let Some(awaiting) = self.awaiting_command.take() {
            // Only one command per connection: a refusal ends it. The
            // command goes with the login and key the token came with.
            if awaiting.login != login || awaiting.fingerprint != fingerprint {
                return Ok(self.refuse(Refused::new("invalid_login", anyhow!("login changed"))));
            }
            let command = match String::from_utf8(answer.to_vec()) {
                Ok(command) if command.is_empty() => {
                    Err(Refused::new("denied", anyhow!("token refused, and no command given")))
                }
                Ok(command) => command
                    .parse::<Command>()
                    .map_err(|e| Refused::new("invalid_command", e.into())),
                Err(_) => Err(Refused::new("invalid_command", anyhow!("not UTF-8"))),
            };
            let result = match command {
                Ok(command) => {
                    self.authenticate(login, fingerprint, awaiting.token, Some(command))
                        .await
                }
                Err(refused) => Err(refused),
            };
            return Ok(match result {
                Ok(()) => Auth::Accept,
                Err(refused) => self.refuse(refused),
            });
        }
        // The token comes in parts, see `bastion_login`.
        let token = match self.token_parts.push(&String::from_utf8_lossy(&answer)) {
            Ok(Progress::Next(part)) => return Ok(ask_token_part(part)),
            Ok(Progress::Done(token)) => token,
            Err(e) => return Ok(self.refuse(Refused::new("invalid_token", e.into()))),
        };
        match self.authenticate(login, fingerprint.clone(), token.clone(), None).await {
            Ok(()) => Ok(Auth::Accept),
            // The token may only allow sessions forced to a command: ask
            // for it. Nothing is inferred from the refusal, which looks the
            // same to the client either way.
            Err(refused) if refused.kind == "denied" => {
                tracing::info!(parent: &self.span, error = %refused.detail, "refused without a command, asking for one");
                self.awaiting_command = Some(AwaitingCommand {
                    login: login.to_owned(),
                    fingerprint,
                    token,
                });
                Ok(ask_command())
            }
            Err(refused) => Ok(self.refuse(refused)),
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
        match until_cut(cut, self.open_channel(id, client)).await {
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
        if let Some(channel) = self.container_channel(id) {
            let pty = container::Pty {
                term: term.to_owned(),
                width: u16::try_from(col_width).unwrap_or(u16::MAX),
                height: u16::try_from(row_height).unwrap_or(u16::MAX),
            };
            match channel.request_pty(pty) {
                Ok(()) => session.channel_success(id)?,
                Err(_) => session.channel_failure(id)?,
            }
            return Ok(());
        }
        let size = (col_width, row_height, pix_width, pix_height);
        let reply = self.forward(id, Request::Pty { term, size, modes }).await?;
        self.answer(id, reply, session).await
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, "shell");
        if self.container_channel(id).is_some() {
            return self.start_in_container(id, None, session).await;
        }
        let reply = self.forward(id, Request::Shell).await?;
        self.answer(id, reply, session).await
    }

    async fn exec_request(&mut self, id: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, command = %String::from_utf8_lossy(command), "exec");
        if self.container_channel(id).is_some() {
            return self.start_in_container(id, Some(command), session).await;
        }
        let reply = self.forward(id, Request::Exec(command)).await?;
        self.answer(id, reply, session).await
    }

    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!(parent: &self.span, subsystem = name, "subsystem");
        if self.container_channel(id).is_some() {
            // Containers have no subsystems such as sftp.
            session.channel_failure(id)?;
            return Ok(());
        }
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
        if self.container_channel(id).is_some() {
            let docker = self.docker()?;
            let cut = self.cut.clone();
            let channel = self.container_channel(id).context("unknown channel")?;
            let (width, height) = (
                u16::try_from(col_width).unwrap_or(u16::MAX),
                u16::try_from(row_height).unwrap_or(u16::MAX),
            );
            // A failed resize keeps the previous size: not worth ending the session.
            let _ = until_cut(cut, channel.resize(&docker, width, height)).await;
            return Ok(());
        }
        until_cut(self.cut.clone(), async {
            let to_target = &self.relay(id)?.to_target;
            Ok(to_target
                .window_change(col_width, row_height, pix_width, pix_height)
                .await?)
        })
        .await
    }

    async fn signal(&mut self, id: ChannelId, signal: Sig, _: &mut Session) -> Result<(), Self::Error> {
        if self.container_channel(id).is_some() {
            // Docker cannot signal an exec.
            return Ok(());
        }
        until_cut(self.cut.clone(), async {
            Ok(self.relay(id)?.to_target.signal(signal).await?)
        })
        .await
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], _: &mut Session) -> Result<(), Self::Error> {
        let cut = self.cut.clone();
        if let Some(channel) = self.container_channel(id) {
            return until_cut(cut, channel.write(data)).await;
        }
        until_cut(self.cut.clone(), async {
            let to_target = &self.relay(id)?.to_target;
            Ok(to_target.data_bytes(Bytes::copy_from_slice(data)).await?)
        })
        .await
    }

    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        let cut = self.cut.clone();
        match self.channels.get_mut(&id) {
            Some(SessionChannel::Ssh(relay)) => until_cut(cut, async { Ok(relay.to_target.eof().await?) }).await,
            Some(SessionChannel::Container(channel)) => until_cut(cut, channel.eof()).await,
            None => Ok(()),
        }
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(SessionChannel::Ssh(relay)) = self.channels.remove(&id) {
            let _ = until_cut(self.cut.clone(), async { Ok(relay.to_target.close().await?) }).await;
        }
        Ok(())
    }
}
