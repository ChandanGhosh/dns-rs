//! Client for the daemon's local control socket.
//!
//! The container image is based on `scratch`, so the daemon binary is the only
//! tool available inside a container. This client sends one request to an
//! existing socket and prints the response; it never binds or listens.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use dns_control::ControlCommand;

/// Options supplied on the command line.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a> {
    /// Socket path. Defaults to the first enabled `control-interface`.
    pub socket: Option<&'a Path>,
    /// Command to send.
    pub command: ControlCommand,
}

/// Run one control command against a running daemon.
///
/// # Errors
///
/// Returns an error when the configuration cannot be loaded, no socket is
/// configured, the connection fails, or the daemon replies with an error.
pub fn run(config_path: &Path, options: &Options<'_>) -> Result<()> {
    let socket = match options.socket {
        Some(path) => path.to_path_buf(),
        None => socket_from_config(config_path)?,
    };
    send(&socket, options.command)
}

fn socket_from_config(path: &Path) -> Result<PathBuf> {
    let loaded = dns_config::load(path)
        .with_context(|| format!("failed to load configuration {}", path.display()))?;
    let control = &loaded.config.remote_control;
    if !control.enabled {
        bail!(
            "remote-control is disabled in {}; enable it or pass --socket",
            path.display()
        );
    }
    control
        .interfaces
        .first()
        .cloned()
        .context("no control-interface configured; pass --socket")
}

/// Send one request and print the response.
///
/// The socket path comes from the local configuration, and the server checks
/// the peer's effective UID, so this client cannot be used to reach another
/// user's daemon.
#[cfg(unix)]
fn send(path: &Path, command: ControlCommand) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use dns_control::{CONNECTION_TIMEOUT, ControlRequest, ControlResponse, MAX_RESPONSE_BYTES};

    /// A reload re-reads the file and may resolve upstream hostnames, so it can
    /// take longer than a status or statistics request.
    const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

    let timeout = if command == ControlCommand::Reload {
        RELOAD_TIMEOUT
    } else {
        CONNECTION_TIMEOUT
    };
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("failed to connect to control socket {}", path.display()))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set the control read timeout")?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set the control write timeout")?;

    let mut request = serde_json::to_vec(&ControlRequest { command })
        .context("failed to encode the control request")?;
    request.push(b'\n');
    stream
        .write_all(&request)
        .context("failed to send the control request")?;

    let mut response = Vec::new();
    // Read through a capped adapter so a hostile local peer cannot make the
    // client allocate without bound.
    stream
        .take((MAX_RESPONSE_BYTES as u64) + 1)
        .read_to_end(&mut response)
        .context("failed to read the control response")?;
    if response.len() > MAX_RESPONSE_BYTES {
        bail!("control response exceeds the {MAX_RESPONSE_BYTES}-byte limit");
    }
    let response = response.trim_suffix(b"\n");
    let response: ControlResponse =
        serde_json::from_slice(response).context("failed to decode the control response")?;

    match response {
        ControlResponse::Status(info) => println!(
            "version={} pid={} uptime={}s protocol={}",
            info.version, info.pid, info.uptime_secs, info.protocol
        ),
        ControlResponse::Stats(stats) => {
            println!(
                "{}",
                serde_json::to_string(&stats).context("failed to encode the statistics")?
            );
        }
        ControlResponse::Prometheus { text } => print!("{text}"),
        ControlResponse::Reloaded => println!("reloaded"),
        ControlResponse::Stopping => println!("stopping"),
        ControlResponse::Error { message } => bail!("{message}"),
    }
    Ok(())
}

#[cfg(not(unix))]
fn send(_path: &Path, _command: ControlCommand) -> Result<()> {
    bail!("the control socket is only supported on Unix")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::socket_from_config;

    #[test]
    fn uses_the_first_configured_socket() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs.sock
    control-interface: /run/dns-rs-2.sock
"#,
        )
        .expect("write config");

        assert_eq!(
            socket_from_config(&path).expect("configured socket"),
            PathBuf::from("/run/dns-rs.sock")
        );
    }

    #[test]
    fn rejects_disabled_control() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(&path, "server:\n    interface: 127.0.0.1@5353\n").expect("write config");

        let error = socket_from_config(&path).expect_err("disabled control");
        assert!(error.to_string().contains("remote-control is disabled"));
    }
}
