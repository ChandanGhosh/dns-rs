//! Unix-domain socket transport for the control protocol.
//!
//! The socket is created with mode `0600` and every accepted connection is
//! checked against the daemon's effective UID with `SO_PEERCRED` (or
//! `getpeereid`). No network transport exists, so a remote client cannot reach
//! the control channel even if it learns the socket path.

use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    CONNECTION_TIMEOUT, ControlCommand, ControlRequest, ControlResponse, ControlService,
    MAX_CONNECTIONS, MAX_REQUEST_BYTES,
};

/// An error from binding or running the control socket.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The configured path is not absolute.
    #[error("control socket path must be absolute: {0}")]
    RelativePath(PathBuf),

    /// The parent of the configured path is not a directory.
    #[error("control socket parent is not a directory: {0}")]
    NotDirectory(PathBuf),

    /// The parent directory is writable by other users without the sticky bit,
    /// so another local user could replace the socket between bind and use.
    #[error(
        "control socket parent directory is group- or other-writable without the sticky bit: {0}"
    )]
    InsecureDirectory(PathBuf),

    /// An existing path was not a socket, was a symlink, or belonged to another
    /// user.
    #[error("refusing to use control socket path {path}: {reason}")]
    UnsafePath {
        /// Offending path.
        path: PathBuf,
        /// Why the path cannot be reused.
        reason: &'static str,
    },

    /// Another process is already serving the configured socket.
    #[error("control socket is already in use: {0}")]
    InUse(PathBuf),

    /// An operation on the control socket path failed.
    #[error("control socket path {path}: {source}")]
    PathIo {
        /// Path being operated on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Accepting or servicing a control connection failed.
    #[error("control socket I/O error: {0}")]
    Io(#[from] io::Error),
}

/// A bound control socket.
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    owner: u32,
    guard: SocketGuard,
}

impl Server {
    /// Bind a control socket at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] when the path is relative, lives in an
    /// insecure directory, is occupied by a live or foreign socket, or cannot
    /// be created with mode `0600`.
    ///
    /// # Security
    ///
    /// A stale socket owned by the effective UID is removed automatically. A
    /// live socket, a regular file, a symlink, or a socket owned by another
    /// user is never replaced.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, ControlError> {
        let path = path.as_ref().to_path_buf();
        validate_path(&path)?;

        let listener = UnixListener::bind(&path).map_err(|source| ControlError::PathIo {
            path: path.clone(),
            source,
        })?;

        // The socket exists now. Remove it again if the remaining setup fails
        // so a failed start does not leave a path behind.
        let identity = fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .and_then(|()| fs::symlink_metadata(&path));
        let metadata = match identity {
            Ok(metadata) => metadata,
            Err(source) => {
                let _ = fs::remove_file(&path);
                return Err(ControlError::PathIo { path, source });
            }
        };

        Ok(Self {
            listener,
            owner: effective_uid(),
            guard: SocketGuard {
                path,
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        })
    }

    /// Serve control connections until `shutdown` is cancelled.
    ///
    /// At most [`MAX_CONNECTIONS`] connections are handled concurrently, and
    /// each connection has [`CONNECTION_TIMEOUT`] to send one request and read
    /// its response.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot accept connections. Individual
    /// connection failures are logged and do not stop the server.
    pub async fn run(
        self,
        service: Arc<dyn ControlService>,
        shutdown: CancellationToken,
    ) -> Result<(), ControlError> {
        let Self {
            listener,
            owner,
            guard: _guard,
        } = self;
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            let stream = tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    debug!("control socket shutting down");
                    return Ok(());
                }
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => return Err(ControlError::Io(error)),
                },
            };

            match stream.peer_cred() {
                Ok(credentials) if credentials.uid() == owner => {}
                Ok(credentials) => {
                    // Local only, but log at debug so a local user cannot
                    // flood the log with rejected connections.
                    debug!(
                        uid = credentials.uid(),
                        "control connection from a different uid rejected"
                    );
                    continue;
                }
                Err(error) => {
                    debug!(%error, "control peer credentials unavailable; rejected");
                    continue;
                }
            }

            let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                debug!("control connection limit reached; rejected");
                continue;
            };
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = serve_connection(stream, service).await {
                    debug!(%error, "control connection closed with an error");
                }
            });
        }
    }
}

/// Removes the socket path on shutdown, but only if it still refers to the
/// socket this process created.
#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_path(path: &Path) -> Result<(), ControlError> {
    if !path.is_absolute() {
        return Err(ControlError::RelativePath(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ControlError::RelativePath(path.to_path_buf()))?;
    let parent_metadata = fs::metadata(parent).map_err(|source| ControlError::PathIo {
        path: parent.to_path_buf(),
        source,
    })?;
    if !parent_metadata.is_dir() {
        return Err(ControlError::NotDirectory(parent.to_path_buf()));
    }
    let mode = parent_metadata.mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(ControlError::InsecureDirectory(parent.to_path_buf()));
    }

    let uid = effective_uid();
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "the path is a symbolic link",
                });
            }
            if !metadata.file_type().is_socket() {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "the path exists and is not a socket",
                });
            }
            if metadata.uid() != uid {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "the existing socket is owned by another user",
                });
            }
            match StdUnixStream::connect(path) {
                Ok(_) => return Err(ControlError::InUse(path.to_path_buf())),
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    fs::remove_file(path).map_err(|source| ControlError::PathIo {
                        path: path.to_path_buf(),
                        source,
                    })?;
                }
                Err(source) => {
                    return Err(ControlError::PathIo {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ControlError::PathIo {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

/// The process's effective UID, used to authorize peers.
#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and only reads the
    // process credential.
    unsafe { libc::geteuid() }
}

async fn serve_connection(
    mut stream: UnixStream,
    service: Arc<dyn ControlService>,
) -> io::Result<()> {
    let request = match tokio::time::timeout(CONNECTION_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(Ok(request))) => request,
        Ok(Ok(Err(message))) => {
            return write_response(&mut stream, &ControlResponse::Error { message }).await;
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return write_response(
                &mut stream,
                &ControlResponse::Error {
                    message: format!(
                        "request timed out after {} seconds",
                        CONNECTION_TIMEOUT.as_secs()
                    ),
                },
            )
            .await;
        }
    };

    let stop = request.command == ControlCommand::Stop;
    let response = dispatch(&*service, request.command).await;
    write_response(&mut stream, &response).await?;
    if stop {
        service.stop();
    }
    Ok(())
}

async fn dispatch(service: &dyn ControlService, command: ControlCommand) -> ControlResponse {
    match command {
        ControlCommand::Status => ControlResponse::Status(service.status()),
        ControlCommand::Stats => ControlResponse::Stats(service.stats()),
        ControlCommand::StatsPrometheus => ControlResponse::Prometheus {
            text: service.prometheus(),
        },
        ControlCommand::Reload => match service.reload().await {
            Ok(()) => ControlResponse::Reloaded,
            Err(message) => ControlResponse::Error { message },
        },
        ControlCommand::Stop => ControlResponse::Stopping,
    }
}

/// Read one bounded, newline-terminated JSON request.
///
/// The outer `io::Result` reports socket failures. The inner `Result` reports
/// protocol problems that are answered with an error response.
async fn read_request(stream: &mut UnixStream) -> io::Result<Result<ControlRequest, String>> {
    let mut buffer = Vec::with_capacity(MAX_REQUEST_BYTES + 1);
    loop {
        if let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
            if position > MAX_REQUEST_BYTES {
                return Ok(Err(format!(
                    "request exceeds the {MAX_REQUEST_BYTES}-byte limit"
                )));
            }
            buffer.truncate(position);
            break;
        }
        if buffer.len() > MAX_REQUEST_BYTES {
            return Ok(Err(format!(
                "request exceeds the {MAX_REQUEST_BYTES}-byte limit"
            )));
        }
        let mut chunk = [0u8; 512];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    while buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    if buffer.is_empty() {
        return Ok(Err("empty request".to_owned()));
    }
    match serde_json::from_slice(&buffer) {
        Ok(request) => Ok(Ok(request)),
        Err(error) => Ok(Err(format!("invalid request: {error}"))),
    }
}

async fn write_response(stream: &mut UnixStream, response: &ControlResponse) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(response).map_err(io::Error::other)?;
    encoded.push(b'\n');
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        stream.write_all(&encoded).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "control response timed out"))?
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::{StatsSnapshot, StatusInfo};

    struct TestService {
        shutdown: CancellationToken,
        stopped: AtomicBool,
    }

    impl TestService {
        fn new(shutdown: CancellationToken) -> Arc<Self> {
            Arc::new(Self {
                shutdown,
                stopped: AtomicBool::new(false),
            })
        }
    }

    impl ControlService for TestService {
        fn status(&self) -> StatusInfo {
            StatusInfo {
                version: "test".to_owned(),
                pid: 7,
                uptime_secs: 3,
                protocol: crate::PROTOCOL_VERSION,
            }
        }

        fn stats(&self) -> StatsSnapshot {
            StatsSnapshot {
                cache_hits: 11,
                ..StatsSnapshot::default()
            }
        }

        fn prometheus(&self) -> String {
            "dns_rs_cache_hits_total 11\n".to_owned()
        }

        fn reload(&self) -> crate::ReloadFuture<'_> {
            Box::pin(async { Ok(()) })
        }

        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
            self.shutdown.cancel();
        }
    }

    /// Tempdirs inherit a permissive umask on some systems; force owner-only
    /// mode so the directory passes the control-socket ownership checks.
    fn secure_tempdir() -> TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secure tempdir");
        directory
    }

    fn socket_path(directory: &TempDir) -> PathBuf {
        directory.path().join("dns-rs.sock")
    }

    async fn exchange(path: &Path, request: &[u8]) -> ControlResponse {
        tokio::time::timeout(Duration::from_secs(2), exchange_inner(path, request))
            .await
            .expect("control exchange timed out")
    }

    async fn exchange_inner(path: &Path, request: &[u8]) -> ControlResponse {
        let mut stream = UnixStream::connect(path).await.expect("connect");
        stream.write_all(request).await.expect("write request");
        stream.shutdown().await.expect("shutdown write");
        let mut response = String::new();
        stream.read_to_string(&mut response).await.expect("read");
        let line = response.strip_suffix('\n').expect("trailing newline");
        serde_json::from_str(line).expect("decode response")
    }

    fn start(
        path: &Path,
    ) -> (
        Arc<TestService>,
        CancellationToken,
        tokio::task::JoinHandle<Result<(), ControlError>>,
    ) {
        let shutdown = CancellationToken::new();
        let service = TestService::new(shutdown.clone());
        let server = Server::bind(path).expect("bind control socket");
        let handle = tokio::spawn(server.run(service.clone(), shutdown.clone()));
        (service, shutdown, handle)
    }

    #[tokio::test]
    async fn binds_with_owner_only_permissions() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let server = Server::bind(&path).expect("bind");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(server);
        assert!(!path.exists(), "shutdown must remove the socket");
    }

    #[test]
    fn rejects_relative_paths() {
        let error = Server::bind("dns-rs.sock").expect_err("relative path");
        assert!(matches!(error, ControlError::RelativePath(_)));
    }

    #[test]
    fn rejects_non_socket_paths() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        fs::write(&path, b"not a socket").expect("write file");
        let error = Server::bind(&path).expect_err("regular file");
        assert!(matches!(error, ControlError::UnsafePath { .. }));
        assert!(path.exists(), "an unsafe path must not be removed");
    }

    #[test]
    fn rejects_symlinks() {
        let directory = secure_tempdir();
        let target = directory.path().join("target");
        fs::write(&target, b"not a socket").expect("write file");
        let path = socket_path(&directory);
        symlink(&target, &path).expect("symlink");
        let error = Server::bind(&path).expect_err("symlink");
        assert!(matches!(error, ControlError::UnsafePath { .. }));
        assert!(path.exists(), "a symlink must not be removed");
    }

    #[test]
    fn rejects_world_writable_parent_without_sticky_bit() {
        let directory = secure_tempdir();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
            .expect("chmod parent");
        let error = Server::bind(socket_path(&directory)).expect_err("insecure parent");
        assert!(matches!(error, ControlError::InsecureDirectory(_)));
    }

    #[tokio::test]
    async fn replaces_a_stale_socket() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let stale = std::os::unix::net::UnixListener::bind(&path).expect("stale listener");
        drop(stale);
        assert!(path.exists());

        let server = Server::bind(&path).expect("replace stale socket");
        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn refuses_a_live_socket() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("live listener");
        let error = Server::bind(&path).expect_err("live socket");
        assert!(matches!(error, ControlError::InUse(_)));
        drop(listener);
    }

    #[tokio::test]
    async fn serves_stats_and_removes_the_socket() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (_service, shutdown, handle) = start(&path);

        let response = exchange(&path, b"{\"command\":\"stats\"}\n").await;
        assert_eq!(
            response,
            ControlResponse::Stats(StatsSnapshot {
                cache_hits: 11,
                ..StatsSnapshot::default()
            })
        );

        shutdown.cancel();
        handle.await.expect("join").expect("run");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn serves_status_and_prometheus() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (_service, shutdown, handle) = start(&path);

        let status = exchange(&path, b"{\"command\":\"status\"}\n").await;
        assert_eq!(
            status,
            ControlResponse::Status(StatusInfo {
                version: "test".to_owned(),
                pid: 7,
                uptime_secs: 3,
                protocol: crate::PROTOCOL_VERSION,
            })
        );

        let prometheus = exchange(&path, b"{\"command\":\"stats-prometheus\"}\n").await;
        assert_eq!(
            prometheus,
            ControlResponse::Prometheus {
                text: "dns_rs_cache_hits_total 11\n".to_owned()
            }
        );

        shutdown.cancel();
        handle.await.expect("join").expect("run");
    }

    #[tokio::test]
    async fn reload_reports_success() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (_service, shutdown, handle) = start(&path);

        let response = exchange(&path, b"{\"command\":\"reload\"}\n").await;
        assert_eq!(response, ControlResponse::Reloaded);

        shutdown.cancel();
        handle.await.expect("join").expect("run");
    }

    #[tokio::test]
    async fn rejects_malformed_and_unknown_requests() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (_service, shutdown, handle) = start(&path);

        for request in [
            b"not json\n".as_slice(),
            b"{\"command\":\"exec\"}\n".as_slice(),
            b"{\"command\":\"stats\",\"arg\":\"sh\"}\n".as_slice(),
            b"\n".as_slice(),
        ] {
            let response = exchange(&path, request).await;
            assert!(
                matches!(response, ControlResponse::Error { .. }),
                "expected an error for {request:?}"
            );
        }

        shutdown.cancel();
        handle.await.expect("join").expect("run");
    }

    #[tokio::test]
    async fn rejects_oversized_requests() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (_service, shutdown, handle) = start(&path);

        let oversized = vec![b'a'; MAX_REQUEST_BYTES + 1];
        let response = exchange(&path, &oversized).await;
        assert!(matches!(response, ControlResponse::Error { .. }));

        shutdown.cancel();
        handle.await.expect("join").expect("run");
    }

    #[tokio::test]
    async fn stop_acknowledges_before_shutting_down() {
        let directory = secure_tempdir();
        let path = socket_path(&directory);
        let (service, _shutdown, handle) = start(&path);

        let response = exchange(&path, b"{\"command\":\"stop\"}\n").await;
        assert_eq!(response, ControlResponse::Stopping);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("server stopped after the stop command")
            .expect("join")
            .expect("run");
        assert!(service.stopped.load(Ordering::SeqCst));
        assert!(!path.exists());
    }
}
