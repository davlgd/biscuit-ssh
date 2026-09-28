//! The Docker operations of a sandbox: pull, run, check, remove.
//!
//! Containers run without network but loopback (the bastion reaches them
//! through the Docker API, not over the network), with bounded memory, CPU,
//! processes and logs, a reduced set of capabilities, and cannot gain
//! privileges. Every operation addresses a container by its immutable ID,
//! except the lookup of a name left over by a crash, which is checked
//! against this instance's label.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use bollard::Docker;
use bollard::errors::Error as DockerError;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{ContainerCreateBody, HostConfig, HostConfigLogConfig};
use bollard::query_parameters::{
    CreateContainerOptions, CreateImageOptions, InspectContainerOptions, ListContainersOptions, RemoveContainerOptions,
};
use futures_util::StreamExt;

use crate::image::ImageRef;

/// Resource limits of each sandbox.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Memory, in bytes.
    pub memory: i64,
    /// CPU, in billionths of a CPU.
    pub nano_cpus: i64,
    /// Processes.
    pub pids: i64,
    /// Writable layer size, e.g. `2G`, when Docker's storage supports it
    /// (overlay2 on XFS with project quotas).
    pub disk: Option<String>,
}

/// Why an image cannot be pulled.
#[derive(Debug, thiserror::Error)]
pub enum PullError {
    /// The repository, tag or digest does not exist (or is private).
    #[error("image not found")]
    NotFound,
    /// No variant of the image runs on this host.
    #[error("image not available for this platform")]
    Platform,
    /// Docker Hub or the daemon failed; details are logged.
    #[error("registry error")]
    Registry,
    /// The pull took too long.
    #[error("pull timed out")]
    Timeout,
}

/// Pulls `image` and returns the ID of the image pulled, so the container
/// runs exactly that image even if the tag moves meanwhile.
pub async fn pull(docker: &Docker, image: &ImageRef, timeout: Duration) -> Result<String, PullError> {
    let options = CreateImageOptions {
        from_image: Some(image.repository()),
        tag: Some(image.version().to_owned()),
        ..Default::default()
    };
    let pulling = async {
        let mut progress = docker.create_image(Some(options), None, None);
        while let Some(item) = progress.next().await {
            item.map_err(classify_pull_error)?;
        }
        let pulled = match image.version() {
            version if version.starts_with("sha256:") => format!("{}@{version}", image.repository()),
            version => format!("{}:{version}", image.repository()),
        };
        let inspected = docker.inspect_image(&pulled).await.map_err(|e| {
            tracing::warn!(error = %e, "cannot inspect a pulled image");
            PullError::Registry
        })?;
        if inspected.os.as_deref() != Some("linux") {
            return Err(PullError::Platform);
        }
        inspected.id.ok_or(PullError::Registry)
    };
    tokio::time::timeout(timeout, pulling)
        .await
        .map_err(|_| PullError::Timeout)?
}

/// Tells a missing image apart from other failures. Docker only reports
/// them as text, so this matches the messages it and Docker Hub use.
fn classify_pull_error(error: DockerError) -> PullError {
    let message = error.to_string().to_lowercase();
    if matches!(error, DockerError::DockerResponseServerError { status_code: 404, .. })
        || message.contains("manifest unknown")
        || message.contains("not found")
        || message.contains("repository does not exist")
    {
        PullError::NotFound
    } else if message.contains("no matching manifest") {
        PullError::Platform
    } else {
        tracing::warn!(error = %error, "pull failed");
        PullError::Registry
    }
}

/// Creates and starts container `name` from `image_id`, labelled
/// `label=instance`; returns its ID.
pub async fn run(
    docker: &Docker,
    name: &str,
    image_id: &str,
    (label, instance): (&str, &str),
    limits: &Limits,
) -> anyhow::Result<String> {
    let body = ContainerCreateBody {
        image: Some(image_id.to_owned()),
        labels: Some(HashMap::from([(label.to_owned(), instance.to_owned())])),
        // Like `docker run -dit`: images whose command is a shell keep running.
        tty: Some(true),
        open_stdin: Some(true),
        host_config: Some(HostConfig {
            network_mode: Some("none".to_owned()),
            memory: Some(limits.memory),
            memory_swap: Some(limits.memory),
            nano_cpus: Some(limits.nano_cpus),
            pids_limit: Some(limits.pids),
            security_opt: Some(vec!["no-new-privileges".to_owned()]),
            // Only what a shell session commonly needs as root: files and
            // processes of its own; no raw sockets, devices, chroot or
            // capability changes.
            cap_drop: Some(vec!["ALL".to_owned()]),
            cap_add: Some(
                ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID"]
                    .map(str::to_owned)
                    .to_vec(),
            ),
            storage_opt: limits
                .disk
                .clone()
                .map(|size| HashMap::from([("size".to_owned(), size)])),
            log_config: Some(HostConfigLogConfig {
                typ: Some("json-file".to_owned()),
                config: Some(HashMap::from([
                    ("max-size".to_owned(), "1m".to_owned()),
                    ("max-file".to_owned(), "1".to_owned()),
                ])),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let options = CreateContainerOptions {
        name: Some(name.to_owned()),
        ..Default::default()
    };
    let created = docker
        .create_container(Some(options), body)
        .await
        .context("cannot create the container")?;
    docker
        .start_container(&created.id, None)
        .await
        .context("cannot start the container")?;
    Ok(created.id)
}

/// Why a container cannot be a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// Its command ended at once.
    Exited,
    /// `/bin/sh` does not run in it.
    NoShell,
    /// Docker could not tell: not the image's fault.
    Unchecked,
}

impl Unusable {
    /// The reason, for clients.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Exited => "its command exits at once (it must keep running, like a shell)",
            Self::NoShell => "/bin/sh does not run in it",
            Self::Unchecked => "Docker could not check it",
        }
    }
}

/// Checks that container `id` keeps running and can run `/bin/sh` as
/// `user`, which sessions through the bastion need.
pub async fn usable(docker: &Docker, id: &str, user: &str) -> Result<(), Unusable> {
    // A command that exits at once would be caught here.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let inspected = docker
        .inspect_container(id, None::<InspectContainerOptions>)
        .await
        .map_err(|_| Unusable::Unchecked)?;
    if inspected.state.and_then(|state| state.running) != Some(true) {
        return Err(Unusable::Exited);
    }
    match tokio::time::timeout(SHELL_TIMEOUT, shell_works(docker, id, user)).await {
        Ok(Ok(true)) => Ok(()),
        _ => Err(Unusable::NoShell),
    }
}

/// Longest the `/bin/sh` check may take.
const SHELL_TIMEOUT: Duration = Duration::from_secs(5);

async fn shell_works(docker: &Docker, id: &str, user: &str) -> anyhow::Result<bool> {
    let exec = docker
        .create_exec(
            id,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["/bin/sh", "-c", "true"]),
                user: Some(user),
                ..Default::default()
            },
        )
        .await?;
    let start = StartExecOptions {
        detach: false,
        tty: false,
        output_capacity: None,
    };
    if let StartExecResults::Attached { mut output, .. } = docker.start_exec(&exec.id, Some(start)).await? {
        while let Some(item) = output.next().await {
            if item.is_err() {
                return Ok(false);
            }
        }
    }
    // Only a command Docker reports as finished has a meaningful status.
    loop {
        let inspected = docker.inspect_exec(&exec.id).await?;
        if inspected.running == Some(false) {
            return Ok(inspected.exit_code == Some(0));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Removes container `id` and its anonymous volumes, stopping it if needed.
/// A container already gone counts as removed.
pub async fn remove(docker: &Docker, id: &str) -> anyhow::Result<()> {
    let options = RemoveContainerOptions {
        force: true,
        v: true,
        ..Default::default()
    };
    match docker.remove_container(id, Some(options)).await {
        Ok(()) | Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
        Err(e) => Err(e).context("cannot remove the container"),
    }
}

/// Whether container `id` exists; `Err` when Docker cannot tell.
pub async fn exists(docker: &Docker, id: &str) -> Result<bool, ()> {
    match docker.inspect_container(id, None::<InspectContainerOptions>).await {
        Ok(_) => Ok(true),
        Err(DockerError::DockerResponseServerError { status_code: 404, .. }) => Ok(false),
        Err(_) => Err(()),
    }
}

/// The containers labelled `label=instance`: (ID, name without its slash).
pub async fn list(docker: &Docker, label: &str, instance: &str) -> anyhow::Result<Vec<(String, String)>> {
    let options = ListContainersOptions {
        all: true,
        filters: Some(HashMap::from([(
            "label".to_owned(),
            vec![format!("{label}={instance}")],
        )])),
        ..Default::default()
    };
    let containers = docker
        .list_containers(Some(options))
        .await
        .context("cannot list containers")?;
    Ok(containers
        .into_iter()
        .filter_map(|c| {
            let name = c.names?.first()?.trim_start_matches('/').to_owned();
            Some((c.id?, name))
        })
        .collect())
}
