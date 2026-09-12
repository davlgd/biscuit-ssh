//! Relaying one session channel between a client and its target.
//!
//! Client requests reach the bastion through russh handler callbacks (see
//! `server.rs`), which forward them to the target and wait for its answer:
//! russh tracks one pending reply per channel, so a request must be answered
//! before the next one is read. Everything coming back from the target goes
//! through [`pump`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use russh::ChannelId;
use russh::ChannelMsg;
use russh::{ChannelReadHalf, ChannelWriteHalf};
use tokio::sync::{oneshot, watch};

/// The target side of a relayed channel.
pub struct Relay {
    /// Sends to the target; shared with the connection's cutter.
    pub to_target: Arc<ChannelWriteHalf<russh::client::Msg>>,
    /// Waiting for the target's answers, in request order.
    pub replies: Replies,
}

/// Pending answers to requests forwarded to a target, in order: the target
/// answers the requests of a channel in the order it received them.
#[derive(Clone, Default)]
pub struct Replies(Arc<Mutex<VecDeque<oneshot::Sender<bool>>>>);

impl Replies {
    /// Registers a request about to be forwarded; the receiver gets the
    /// target's answer. Call it before forwarding, so a fast answer cannot
    /// arrive first.
    pub fn expect(&self) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        self.lock().push_back(sender);
        receiver
    }

    fn answer(&self, success: bool) {
        if let Some(waiting) = self.lock().pop_front() {
            // The requester may have given up (timeout): nothing to do.
            let _ = waiting.send(success);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<oneshot::Sender<bool>>> {
        // A poisoned lock only means another task panicked while holding
        // it; the queue itself is still consistent.
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Copies what the target sends on a channel to the client, until either
/// side closes it or the connection is cut.
pub async fn pump(
    mut from_target: ChannelReadHalf,
    client: russh::server::Handle,
    id: ChannelId,
    replies: Replies,
    mut cut: watch::Receiver<bool>,
) {
    loop {
        let message = tokio::select! {
            message = from_target.wait() => message,
            _ = cut.wait_for(|cut| *cut) => break,
        };
        let Some(message) = message else {
            break;
        };
        let delivered = match message {
            ChannelMsg::Data { data } => client.data(id, data).await.is_ok(),
            ChannelMsg::ExtendedData { data, ext } => client.extended_data(id, ext, data).await.is_ok(),
            ChannelMsg::Eof => client.eof(id).await.is_ok(),
            ChannelMsg::ExitStatus { exit_status } => client.exit_status_request(id, exit_status).await.is_ok(),
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => client
                .exit_signal_request(id, signal_name, core_dumped, error_message, lang_tag)
                .await
                .is_ok(),
            ChannelMsg::Success => {
                replies.answer(true);
                true
            }
            ChannelMsg::Failure => {
                replies.answer(false);
                true
            }
            ChannelMsg::Close => break,
            _ => true,
        };
        if !delivered {
            break;
        }
    }
    let _ = client.close(id).await;
}
