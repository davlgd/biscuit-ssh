//! Sessions in containers, through the Docker Engine API.
//!
//! Containers need no SSH server: each session channel runs one `exec` in
//! the container, as the login account, and relays its input and output.
//! A shell session starts `bash` when the image has it, `sh` otherwise; a
//! command runs through `sh -c`. Images must therefore be Linux images
//! providing `/bin/sh`.
//!
//! Docker offers no way to stop an exec: closing a session, or cutting the
//! connection, stops relaying but lets its processes run until they end or
//! the container is removed.

use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, bail};
use biscuit_ssh_core::Name;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecOptions, StartExecResults};
use futures_util::StreamExt;
use russh::ChannelId;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::config::Containers;

/// Starts the user's login shell, preferring bash.
const SHELL: &str = "command -v bash >/dev/null 2>&1 && exec bash -l || exec sh -l";

/// The ID of the running container named `name` that carries the label, if
/// any. Sessions then address it by that ID, never again by name, so a
/// container recreated under the same name is not reached by mistake.
pub async fn find(containers: &Containers, name: &Name) -> anyhow::Result<Option<String>> {
    let inspected = match containers.docker.inspect_container(name.as_str(), None).await {
        Ok(inspected) => inspected,
        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => return Ok(None),
        Err(e) => return Err(e).context("cannot inspect the container"),
    };
    let labelled = inspected
        .config
        .and_then(|config| config.labels)
        .is_some_and(|labels| labels.contains_key(&containers.label));
    // Docker reports names with a leading slash.
    let named = inspected.name.as_deref().map(|n| n.trim_start_matches('/')) == Some(name.as_str());
    let running = inspected.state.and_then(|state| state.running) == Some(true);
    Ok(inspected.id.filter(|_| labelled && named && running))
}

/// Terminal requested for a session.
#[derive(Debug, Clone)]
pub struct Pty {
    /// Value of `TERM`.
    pub term: String,
    /// Columns.
    pub width: u16,
    /// Rows.
    pub height: u16,
}

/// A session channel run in a container: a terminal request, then one
/// command.
#[derive(Default)]
pub struct ContainerChannel {
    pty: Option<Pty>,
    exec: Option<Exec>,
}

struct Exec {
    id: String,
    /// `None` once the client sent EOF. In a mutex only to make sessions
    /// shareable between threads, as russh requires; it is never contended.
    input: Option<Mutex<Input>>,
    /// Relays the output; stopped when the channel goes, which closes the
    /// connection to Docker (the command itself keeps running).
    pump: JoinHandle<()>,
}

impl Drop for ContainerChannel {
    fn drop(&mut self) {
        if let Some(exec) = &self.exec {
            exec.pump.abort();
        }
    }
}

type Input = Pin<Box<dyn AsyncWrite + Send>>;

/// Where a started command sends its output.
pub struct Output {
    /// The client's session.
    pub client: russh::server::Handle,
    /// The client's channel.
    pub channel: ChannelId,
    /// Becomes true when the connection is cut.
    pub cut: watch::Receiver<bool>,
}

impl ContainerChannel {
    /// Records the terminal for the command to come; refused once started.
    pub fn request_pty(&mut self, pty: Pty) -> anyhow::Result<()> {
        if self.exec.is_some() {
            bail!("the session already runs a command");
        }
        self.pty = Some(pty);
        Ok(())
    }

    /// Starts `command`, or the login shell, in container `id` as `user`,
    /// and relays its output to the client until it ends.
    pub async fn start(
        &mut self,
        docker: &Docker,
        id: &str,
        user: &str,
        command: Option<&[u8]>,
        output: Output,
    ) -> anyhow::Result<()> {
        if self.exec.is_some() {
            bail!("the session already runs a command");
        }
        let script = match command {
            Some(command) => String::from_utf8(command.to_vec()).context("the command is not UTF-8")?,
            None => SHELL.to_owned(),
        };
        let tty = self.pty.is_some();
        let created = docker
            .create_exec(
                id,
                CreateExecOptions {
                    attach_stdin: Some(true),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    tty: Some(tty),
                    cmd: Some(vec!["/bin/sh".to_owned(), "-c".to_owned(), script]),
                    user: Some(user.to_owned()),
                    env: self.pty.as_ref().map(|pty| vec![format!("TERM={}", pty.term)]),
                    ..Default::default()
                },
            )
            .await
            .context("cannot create the command")?;
        let started = docker
            .start_exec(
                &created.id,
                Some(StartExecOptions {
                    detach: false,
                    tty,
                    output_capacity: None,
                }),
            )
            .await
            .context("cannot start the command")?;
        let StartExecResults::Attached { output: stream, input } = started else {
            bail!("the command started detached");
        };
        if let Some(pty) = &self.pty {
            // Best effort: a failed resize leaves the default size.
            let _ = resize(docker, &created.id, pty.width, pty.height).await;
        }
        let pump = tokio::spawn(pump(docker.clone(), created.id.clone(), stream, output));
        self.exec = Some(Exec {
            id: created.id,
            input: Some(Mutex::new(input)),
            pump,
        });
        Ok(())
    }

    /// Resizes the terminal, before or after the command starts.
    pub async fn resize(&mut self, docker: &Docker, width: u16, height: u16) -> anyhow::Result<()> {
        if let Some(pty) = &mut self.pty {
            pty.width = width;
            pty.height = height;
        }
        match &self.exec {
            Some(exec) => resize(docker, &exec.id, width, height).await,
            None => Ok(()),
        }
    }

    /// Sends input to the command.
    pub async fn write(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let input = self
            .exec
            .as_mut()
            .and_then(|exec| exec.input.as_mut())
            .context("no command is reading input")?;
        let input = input.get_mut();
        input.write_all(data).await?;
        Ok(input.flush().await?)
    }

    /// Closes the command's input; its output keeps flowing.
    ///
    /// Ignored with a terminal, as sshd does: Docker would hang the terminal
    /// up, and the command would lose its output.
    pub async fn eof(&mut self) -> anyhow::Result<()> {
        if self.pty.is_some() {
            return Ok(());
        }
        if let Some(input) = self.exec.as_mut().and_then(|exec| exec.input.take()) {
            input.into_inner().shutdown().await?;
        }
        Ok(())
    }
}

async fn resize(docker: &Docker, exec: &str, width: u16, height: u16) -> anyhow::Result<()> {
    let size = ResizeExecOptions { height, width };
    docker
        .resize_exec(exec, size)
        .await
        .context("cannot resize the terminal")
}

/// Relays a command's output to the client, then its exit status, and
/// closes the channel; stops at once when the connection is cut.
async fn pump(docker: Docker, exec: String, stream: OutputStream, output: Output) {
    let Output {
        client,
        channel,
        mut cut,
    } = output;
    tokio::select! {
        biased;
        _ = cut.wait_for(|cut| *cut) => {}
        () = relay(&docker, &exec, stream, &client, channel) => {}
    }
}

type OutputStream = Pin<Box<dyn futures_util::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>>;

async fn relay(
    docker: &Docker,
    exec: &str,
    mut stream: OutputStream,
    client: &russh::server::Handle,
    channel: ChannelId,
) {
    let ended = loop {
        let delivered = match stream.next().await {
            Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                client.data(channel, message).await.is_ok()
            }
            Some(Ok(LogOutput::StdErr { message })) => client.extended_data(channel, 1, message).await.is_ok(),
            Some(Ok(LogOutput::StdIn { .. })) => true,
            // A broken stream says nothing about how the command ended.
            Some(Err(_)) => break false,
            None => break true,
        };
        if !delivered {
            return;
        }
    };
    let status = match ended {
        true => exit_status(docker, exec).await,
        false => None,
    };
    // Without a status, the client knows the command's outcome is unknown.
    if let Some(status) = status {
        let _ = client.exit_status_request(channel, status).await;
    }
    let _ = client.eof(channel).await;
    let _ = client.close(channel).await;
}

/// The exit status of a command whose output ended, once Docker confirms it
/// is no longer running; `None` if it does not within a few seconds.
async fn exit_status(docker: &Docker, exec: &str) -> Option<u32> {
    let confirmed = async {
        loop {
            let inspected = docker.inspect_exec(exec).await.ok()?;
            if inspected.running == Some(false) {
                return inspected.exit_code.and_then(|code| u32::try_from(code).ok());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), confirmed)
        .await
        .ok()
        .flatten()
}
