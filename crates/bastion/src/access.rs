//! What an authenticated connection may do, and for how long.
//!
//! A connection holds a lease: an authorization covering up to
//! `session_check_interval`. Shortly before it ends, the token is evaluated
//! again for the next window, starting exactly where the lease ends, so the
//! covered time is contiguous and every second the token refuses is caught.
//! The connection is cut when the token stops allowing access, at that exact
//! second; a revocation, or a token that can no longer be checked, is found
//! at the next renewal (so within `session_check_interval`) and cuts it
//! then. Cutting stops relaying at once and closes the sockets at most
//! [`DISCONNECT_GRACE`] later.

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_ssh_core::{AccessRequest, Authorization};
use russh::{Disconnect, Sig};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::{Settings, Target};

/// How long before a lease ends its renewal starts.
const RENEWAL_MARGIN: u64 = 5;

/// An authenticated connection: the token presented and what it was
/// checked for.
pub struct Grant {
    /// The token, kept to evaluate it again during the connection.
    pub token: String,
    /// The request as authenticated; only its time changes afterwards.
    pub request: AccessRequest,
    /// The server connections are relayed to.
    pub target: Target,
}

/// Why a token check failed.
#[derive(Debug)]
pub enum Refusal {
    /// The token does not allow the request at the requested time: the
    /// connection may go on until then.
    Denied,
    /// Revoked, invalid, or the revocation list is unreadable: stop at once.
    Immediate(&'static str),
}

impl Refusal {
    /// A stable, content-free label for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Immediate(kind) => kind,
        }
    }
}

impl Grant {
    /// Evaluates the token for `lifetime` from `time`, against the current
    /// revocation list. Blocking: Datalog.
    pub fn authorize(
        &self,
        settings: &Settings,
        time: SystemTime,
        lifetime: Duration,
    ) -> Result<Authorization, Refusal> {
        let revoked = settings
            .authority
            .revocations()
            .map_err(|_| Refusal::Immediate("revocation_list_unreadable"))?;
        let request = AccessRequest {
            time,
            ..self.request.clone()
        };
        settings
            .authority
            .verifier
            .authorize(&self.token, &request, &revoked, lifetime)
            .map_err(|e| match e {
                biscuit_ssh_core::Error::Denied(_) => Refusal::Denied,
                _ => Refusal::Immediate(e.kind()),
            })
    }
}

/// Keeps renewing the lease of a connection until the token stops allowing
/// it, then cuts the connection.
///
/// Returns early, without cutting, once the connection is gone.
pub async fn guard(
    settings: Arc<Settings>,
    grant: Arc<Grant>,
    mut lease_end: u64,
    client: russh::server::Handle,
    cutter: Arc<Cutter>,
) {
    let reason = loop {
        let deadline = instant_at(lease_end);
        tokio::select! {
            () = tokio::time::sleep_until(instant_at(lease_end.saturating_sub(RENEWAL_MARGIN))) => {}
            () = cutter.gone() => return,
        }
        let (settings, grant) = (Arc::clone(&settings), Arc::clone(&grant));
        let start = UNIX_EPOCH + Duration::from_secs(lease_end);
        let renewal = tokio::task::spawn_blocking(move || grant.authorize(&settings, start, settings.check_interval));
        tokio::select! {
            result = renewal => match result {
                Ok(Ok(authorization)) => lease_end = authorization.valid_until(),
                Ok(Err(Refusal::Denied)) => {
                    // Still allowed until the lease ends, not a second more.
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {}
                        () = cutter.gone() => return,
                    }
                    break "access expired";
                }
                Ok(Err(refusal)) => break refusal.kind(),
                Err(_) => break "internal error",
            },
            () = tokio::time::sleep_until(deadline) => break "renewal too slow",
            () = cutter.gone() => return,
        }
    };
    tracing::warn!(reason, "session cut");
    cutter.cut(&client, reason).await;
}

/// Cuts a connection for good: flags it so pending operations fail, tells
/// the client why, hangs up the target sessions, then closes the client and
/// target sockets. Closing the sockets is what guarantees the cut: russh
/// sessions run in background tasks that a stalled peer could otherwise
/// keep alive.
pub struct Cutter {
    flag: watch::Sender<bool>,
    sockets: Mutex<Vec<Option<std::net::TcpStream>>>,
    sessions: Mutex<Vec<Weak<TargetSession>>>,
}

/// The sending side of a target session channel.
pub type TargetSession = russh::ChannelWriteHalf<russh::client::Msg>;

/// How long a cut connection may wind down gracefully (hang-ups and
/// disconnection notice sent) before its sockets are closed.
const DISCONNECT_GRACE: Duration = Duration::from_secs(2);

/// Time left to queued messages once the connection is gone.
const FLUSH_DELAY: Duration = Duration::from_millis(200);

impl Cutter {
    /// A cutter for a connection on `client_socket` (a duplicate of the
    /// socket the SSH session uses).
    pub fn new(client_socket: std::net::TcpStream) -> Arc<Self> {
        Arc::new(Self {
            flag: watch::channel(false).0,
            sockets: Mutex::new(vec![Some(client_socket)]),
            sessions: Mutex::new(Vec::new()),
        })
    }

    /// Also closes `socket` on cut, or right away if already cut, until
    /// the returned registration is dropped without being kept.
    pub fn watch_socket(&self, socket: std::net::TcpStream) -> WatchedSocket<'_> {
        let mut sockets = lock(&self.sockets);
        if *self.flag.borrow() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        // Reuse the slot of a forgotten socket, so failures cannot grow the list.
        let index = match sockets.iter().position(Option::is_none) {
            Some(free) => {
                sockets[free] = Some(socket);
                free
            }
            None => {
                sockets.push(Some(socket));
                sockets.len() - 1
            }
        };
        WatchedSocket {
            cutter: self,
            index,
            kept: false,
        }
    }

    /// Also hangs up `session` on cut, while it is open.
    pub fn watch_session(&self, session: &Arc<TargetSession>) {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|session| session.strong_count() > 0);
        sessions.push(Arc::downgrade(session));
    }

    /// Becomes true when the connection is cut. The connection counts as
    /// gone once every receiver is dropped.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.flag.subscribe()
    }

    async fn gone(&self) {
        self.flag.closed().await;
    }

    async fn cut(&self, client: &russh::server::Handle, reason: &str) {
        self.flag.send_replace(true);
        let sessions: Vec<_> = lock(&self.sessions).iter().filter_map(Weak::upgrade).collect();
        let farewell = async {
            // Commands started without a terminal would survive a mere
            // disconnect: sshd only hangs up terminals.
            for session in sessions {
                let _ = session.signal(Sig::HUP).await;
            }
            let notice = format!("biscuit-ssh: {reason}");
            let _ = client
                .disconnect(Disconnect::ByApplication, notice, String::new())
                .await;
            // Messages are only queued: let the sessions send them and end.
            self.gone().await;
            tokio::time::sleep(FLUSH_DELAY).await;
        };
        let _ = tokio::time::timeout(DISCONNECT_GRACE, farewell).await;
        for socket in lock(&self.sockets).iter().flatten() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// A socket registered with a [`Cutter`]. Unless kept, dropping it closes
/// and forgets the socket: a failed connection must not linger until a cut.
pub struct WatchedSocket<'a> {
    cutter: &'a Cutter,
    index: usize,
    kept: bool,
}

impl WatchedSocket<'_> {
    /// Keeps the socket registered for the rest of the connection.
    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for WatchedSocket<'_> {
    fn drop(&mut self) {
        if !self.kept
            && let Some(socket) = lock(&self.cutter.sockets).get_mut(self.index).and_then(Option::take)
        {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock only means a panic elsewhere; the list is intact.
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs `work` unless the connection is cut first, as `cut` reports.
pub async fn until_cut<T>(
    mut cut: watch::Receiver<bool>,
    work: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::select! {
        // Checked first, so nothing starts once the connection is cut.
        biased;
        _ = cut.wait_for(|cut| *cut) => anyhow::bail!("connection cut"),
        result = work => result,
    }
}

/// The instant corresponding to `seconds` since the Unix epoch, or now if
/// that is already past.
fn instant_at(seconds: u64) -> Instant {
    let at = UNIX_EPOCH + Duration::from_secs(seconds);
    Instant::now() + at.duration_since(SystemTime::now()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A connected pair of sockets: (ours, the peer's).
    fn socket_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ours = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (ours, listener.accept().unwrap().0)
    }

    fn peer_sees_eof(peer: &mut std::net::TcpStream) -> bool {
        use std::io::Read;
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        matches!(peer.read(&mut [0; 1]), Ok(0))
    }

    #[test]
    fn forgets_sockets_of_failed_connections() {
        let (client, _client_peer) = socket_pair();
        let cutter = Cutter::new(client);

        let (failed, mut failed_peer) = socket_pair();
        drop(cutter.watch_socket(failed));
        assert!(peer_sees_eof(&mut failed_peer), "a failed connection is closed at once");

        let (kept, kept_peer) = socket_pair();
        cutter.watch_socket(kept.try_clone().unwrap()).keep();
        kept_peer.set_nonblocking(true).unwrap();
        assert!(kept_peer.peek(&mut [0; 1]).is_err(), "a kept connection stays open");
        drop(kept);
    }

    #[tokio::test]
    async fn nothing_runs_once_cut() {
        let (flag, cut) = watch::channel(true);
        let runs = AtomicUsize::new(0);
        for _ in 0..1000 {
            let result = until_cut(cut.clone(), async {
                runs.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await;
            assert!(result.is_err());
        }
        assert_eq!(runs.load(Ordering::Relaxed), 0);

        flag.send_replace(false);
        assert!(until_cut(cut, async { Ok(()) }).await.is_ok());
    }
}
