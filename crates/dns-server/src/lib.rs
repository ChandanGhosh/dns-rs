//! DNS listeners and the client-facing query pipeline.

mod acl;
#[cfg(unix)]
mod control;
mod doh;
mod dot;
mod edns;
mod local;
mod phase;
mod pipeline;
#[cfg(unix)]
mod privilege;
mod ratelimit;
#[cfg(target_os = "linux")]
mod recv_batch;
#[cfg(unix)]
mod reload;
#[cfg(target_os = "linux")]
mod send_batch;
mod tcp;
mod tls;
mod udp;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;

use dns_config::Config;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub use pipeline::{PipelineHandle, PipelineStats, QueryPipeline, Transport};

/// Start the `stats phases ...` reporter used by the benchmark runner.
/// Only exists in `phase-stats` builds.
#[cfg(feature = "phase-stats")]
pub use phase::spawn_reporter;

/// Errors that stop the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A listener could not be created or serviced.
    #[error("server I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Downstream TLS material could not be loaded.
    #[error("TLS configuration error: {0}")]
    Tls(String),
    /// The control socket could not be bound or served.
    #[cfg(unix)]
    #[error("control socket error: {0}")]
    Control(#[from] dns_control::ControlError),
    /// The configured `username` could not be resolved or applied.
    #[cfg(unix)]
    #[error("privilege drop failed: {0}")]
    Privilege(String),
}

#[cfg(unix)]
impl From<privilege::PrivilegeError> for ServerError {
    fn from(error: privilege::PrivilegeError) -> Self {
        Self::Privilege(error.to_string())
    }
}

/// Run the server until the shutdown token is cancelled.
pub async fn serve(config: Arc<Config>, shutdown: CancellationToken) -> Result<(), ServerError> {
    serve_inner(config, None, shutdown).await
}

/// Run the server with live configuration reload enabled from `config_path`.
///
/// A reload is triggered by `SIGHUP` or the control socket's `reload` command.
/// It re-reads `config_path`, builds a fresh pipeline (and therefore empty
/// caches), and swaps it in atomically without interrupting in-flight queries.
/// If the file cannot be read, parsed, or validated, the running configuration
/// is kept.
///
/// Settings that are fixed when the listeners are bound (interfaces, ports,
/// TLS files, thread count, socket buffers, control sockets, and verbosity)
/// cannot be applied by a reload. A change to one of them is logged and the
/// running listener is kept; restart the process to apply it.
pub async fn serve_with_reload(
    config: Arc<Config>,
    config_path: PathBuf,
    shutdown: CancellationToken,
) -> Result<(), ServerError> {
    #[cfg(unix)]
    {
        serve_inner(config, Some(config_path), shutdown).await
    }
    #[cfg(not(unix))]
    {
        let _ = config_path;
        warn!("configuration reload is only supported on Unix; starting without it");
        serve_inner(config, None, shutdown).await
    }
}

async fn serve_inner(
    config: Arc<Config>,
    config_path: Option<PathBuf>,
    shutdown: CancellationToken,
) -> Result<(), ServerError> {
    // Resolve the target account before any socket is bound so a typo in
    // `username` fails startup while the process is still privileged. The
    // switch itself happens after listeners and the control socket exist.
    #[cfg(unix)]
    let target_user = config
        .server
        .username
        .as_deref()
        .map(privilege::TargetUser::resolve)
        .transpose()?;
    #[cfg(not(unix))]
    if config.server.username.is_some() {
        warn!("server.username is only supported on Unix; privileges will not be dropped");
    }

    let pipeline = PipelineHandle::new(Arc::clone(&config));
    #[cfg(unix)]
    let reloader = config_path.map(|path| reload::Reloader::new(path, pipeline.clone()));
    #[cfg(not(unix))]
    let _ = config_path;
    // Install the SIGHUP handler before binding anything. If a reload request
    // arrives during startup it is queued and handled once the server is up,
    // instead of taking the default action and terminating the process.
    #[cfg(unix)]
    let hangup = reloader.as_ref().and_then(|_| {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::hangup()) {
            Ok(signal) => Some(signal),
            Err(error) => {
                warn!(%error, "failed to install SIGHUP handler; signal reload is unavailable");
                None
            }
        }
    });
    let tls_material = tls::load(&config.server)?;

    // Unbound's `incoming-num-tcp` is per thread. Enforce the combined limit
    // across every TCP, DoT, and DoH listener so a burst cannot exhaust file
    // descriptors or task memory. (DoH previously had no cap: an idle TLS
    // connection flood could grow tasks and sockets unboundedly.)
    let tcp_capacity = tcp_capacity(&config);
    if config.server.do_tcp && tcp_capacity.is_none() {
        warn!("incoming-num-tcp is 0; TCP, DoT, and DoH listeners are disabled");
    }
    let connections = tcp_capacity.map(|capacity| Arc::new(Semaphore::new(capacity)));

    let mut listeners = Vec::new();
    for iface in &config.server.interfaces {
        let addr = iface.socket_addr(config.server.port);
        if !is_family_allowed(&config, &addr) {
            continue;
        }

        // Unbound selects the listener protocol from the interface port:
        // tls-port serves DoT and https-port serves DoH when TLS material is
        // configured. Every other port serves plain DNS.
        if let Some(acceptor) = tls_material
            .as_ref()
            .filter(|_| addr.port() == config.server.tls_port)
            .map(|material| &material.dot)
        {
            if !config.server.do_tcp {
                continue;
            }
            let Some(connections) = connections.as_ref() else {
                continue;
            };
            {
                let socket =
                    Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                if config.server.tcp_recv_buffer_size > 0
                    && let Err(err) =
                        socket.set_recv_buffer_size(config.server.tcp_recv_buffer_size)
                {
                    warn!(%err, "failed to set TCP receive buffer size");
                }
                if config.server.tcp_send_buffer_size > 0
                    && let Err(err) =
                        socket.set_send_buffer_size(config.server.tcp_send_buffer_size)
                {
                    warn!(%err, "failed to set TCP send buffer size");
                }
                #[cfg(target_os = "linux")]
                if config.server.tcp_user_timeout_ms > 0 {
                    let timeout = Duration::from_millis(config.server.tcp_user_timeout_ms as u64);
                    if let Err(err) = socket.set_tcp_user_timeout(Some(timeout)) {
                        warn!(%err, "failed to set TCP user timeout");
                    }
                }
                socket.set_nonblocking(true)?;
                match socket.bind(&addr.into()) {
                    Ok(()) => {}
                    Err(err) => {
                        error!(%addr, %err, "failed to bind DoT socket");
                        return Err(ServerError::Io(err));
                    }
                }
                if let Err(err) = socket.listen(1024) {
                    error!(%addr, %err, "failed to listen on DoT socket");
                    return Err(ServerError::Io(err));
                }
                let listener = match TcpListener::from_std(socket.into()) {
                    Ok(listener) => listener,
                    Err(err) => {
                        error!(%addr, %err, "failed to convert DoT socket");
                        return Err(ServerError::Io(err));
                    }
                };
                let pipeline = pipeline.clone();
                let shutdown = shutdown.clone();
                let acceptor = acceptor.clone();
                let connections = Arc::clone(connections);
                tokio::spawn(async move {
                    if let Err(err) =
                        dot::run(listener, acceptor, pipeline, shutdown, connections).await
                    {
                        error!(%addr, %err, "DoT listener failed");
                    }
                });
                listeners.push((addr, "dot"));
            }
            continue;
        }

        if let Some(acceptor) = tls_material
            .as_ref()
            .filter(|_| addr.port() == config.server.https_port)
            .map(|material| &material.doh)
        {
            if !config.server.do_tcp {
                continue;
            }
            // DoH shares the TCP/DoT connection pool: like those listeners it
            // needs the cap, and with incoming-num-tcp = 0 it is disabled too.
            let Some(connections) = connections.as_ref() else {
                continue;
            };
            {
                let socket =
                    Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                if config.server.tcp_recv_buffer_size > 0
                    && let Err(err) =
                        socket.set_recv_buffer_size(config.server.tcp_recv_buffer_size)
                {
                    warn!(%err, "failed to set TCP receive buffer size");
                }
                if config.server.tcp_send_buffer_size > 0
                    && let Err(err) =
                        socket.set_send_buffer_size(config.server.tcp_send_buffer_size)
                {
                    warn!(%err, "failed to set TCP send buffer size");
                }
                #[cfg(target_os = "linux")]
                if config.server.tcp_user_timeout_ms > 0 {
                    let timeout = Duration::from_millis(config.server.tcp_user_timeout_ms as u64);
                    if let Err(err) = socket.set_tcp_user_timeout(Some(timeout)) {
                        warn!(%err, "failed to set TCP user timeout");
                    }
                }
                socket.set_nonblocking(true)?;
                match socket.bind(&addr.into()) {
                    Ok(()) => {}
                    Err(err) => {
                        error!(%addr, %err, "failed to bind DoH socket");
                        return Err(ServerError::Io(err));
                    }
                }
                if let Err(err) = socket.listen(1024) {
                    error!(%addr, %err, "failed to listen on DoH socket");
                    return Err(ServerError::Io(err));
                }
                let listener = match TcpListener::from_std(socket.into()) {
                    Ok(listener) => listener,
                    Err(err) => {
                        error!(%addr, %err, "failed to convert DoH socket");
                        return Err(ServerError::Io(err));
                    }
                };
                let pipeline = pipeline.clone();
                let shutdown = shutdown.clone();
                let acceptor = acceptor.clone();
                let endpoint = config.server.http_endpoint.clone();
                let connections = Arc::clone(connections);
                tokio::spawn(async move {
                    if let Err(err) = doh::run(
                        listener,
                        acceptor,
                        endpoint,
                        pipeline,
                        shutdown,
                        connections,
                    )
                    .await
                    {
                        error!(%addr, %err, "DoH listener failed");
                    }
                });
                listeners.push((addr, "doh"));
            }
            continue;
        }

        if config.server.do_udp {
            // SO_REUSEPORT lets the kernel fan datagrams out across several
            // sockets bound to the same address, so each worker gets its own
            // receive loop and the inline hit path runs in parallel instead
            // of through a single loop. Without SO_REUSEPORT (non-unix), only
            // one socket can bind, matching the previous behavior.
            let socket_count = if cfg!(unix) {
                config.server.num_threads.resolve()
            } else {
                1
            };
            for _ in 0..socket_count {
                match udp::bind(
                    addr,
                    config.server.udp_recv_buffer_size,
                    config.server.udp_send_buffer_size,
                ) {
                    Ok(socket) => {
                        let pipeline = pipeline.clone();
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(err) = udp::run(socket, pipeline, shutdown).await {
                                error!(%addr, %err, "UDP listener failed");
                            }
                        });
                    }
                    Err(err) => {
                        error!(%addr, %err, "failed to bind UDP socket");
                        return Err(ServerError::Io(err));
                    }
                }
            }
            listeners.push((addr, "udp"));
        }
        if config.server.do_tcp
            && let Some(connections) = connections.as_ref()
        {
            {
                let socket =
                    Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
                socket.set_reuse_address(true)?;
                #[cfg(unix)]
                socket.set_reuse_port(true)?;
                if config.server.tcp_recv_buffer_size > 0
                    && let Err(err) =
                        socket.set_recv_buffer_size(config.server.tcp_recv_buffer_size)
                {
                    warn!(%err, "failed to set TCP receive buffer size");
                }
                if config.server.tcp_send_buffer_size > 0
                    && let Err(err) =
                        socket.set_send_buffer_size(config.server.tcp_send_buffer_size)
                {
                    warn!(%err, "failed to set TCP send buffer size");
                }
                #[cfg(target_os = "linux")]
                if config.server.tcp_user_timeout_ms > 0 {
                    let timeout = Duration::from_millis(config.server.tcp_user_timeout_ms as u64);
                    if let Err(err) = socket.set_tcp_user_timeout(Some(timeout)) {
                        warn!(%err, "failed to set TCP user timeout");
                    }
                }
                socket.set_nonblocking(true)?;
                match socket.bind(&addr.into()) {
                    Ok(()) => {}
                    Err(err) => {
                        error!(%addr, %err, "failed to bind TCP socket");
                        return Err(ServerError::Io(err));
                    }
                }
                if let Err(err) = socket.listen(1024) {
                    error!(%addr, %err, "failed to listen on TCP socket");
                    return Err(ServerError::Io(err));
                }
                let listener = match TcpListener::from_std(socket.into()) {
                    Ok(listener) => listener,
                    Err(err) => {
                        error!(%addr, %err, "failed to convert TCP socket");
                        return Err(ServerError::Io(err));
                    }
                };
                let pipeline = pipeline.clone();
                let shutdown = shutdown.clone();
                let connections = Arc::clone(connections);
                tokio::spawn(async move {
                    if let Err(err) = tcp::run(listener, pipeline, shutdown, connections).await {
                        error!(%addr, %err, "TCP listener failed");
                    }
                });
                listeners.push((addr, "tcp"));
            }
        }
    }

    // Bind after the DNS listeners so a bad control path fails startup. The
    // socket is created as root and handed to the target user below; creating
    // it after the drop would fail for the usual root-owned `/run` directory.
    #[cfg(unix)]
    let control_paths = if config.remote_control.enabled {
        control::start(
            &config.remote_control,
            pipeline.clone(),
            reloader.clone(),
            shutdown.clone(),
        )?
    } else {
        Vec::new()
    };
    #[cfg(not(unix))]
    if config.remote_control.enabled {
        warn!("remote-control is only supported on Unix; control socket not started");
    }

    #[cfg(unix)]
    if let (Some(reloader), Some(hangup)) = (reloader, hangup) {
        spawn_hangup_handler(reloader, hangup, shutdown.clone());
    }

    #[cfg(unix)]
    if let Some(target) = &target_user {
        if target.is_root() {
            warn!("server.username resolves to root; privileges will not be reduced");
        }
        // The control socket was created with the daemon's original euid. Hand
        // it, and the RFC 5011 state file that the background probe rewrites,
        // to the target account before the switch.
        for path in &control_paths {
            target.ensure_owner(path)?;
        }
        if let Some(path) = &config.server.auto_trust_anchor_file
            && path.exists()
        {
            target.ensure_owner(path)?;
        }
        target.drop_privileges()?;
        info!(
            user = target.display_name(),
            "dropped privileges; listeners and control socket keep their bound resources"
        );
    }
    if listeners.is_empty() {
        warn!("no listeners started");
    } else {
        for (addr, proto) in &listeners {
            info!(%addr, %proto, "listening");
        }
    }

    shutdown.cancelled().await;
    info!("server stopped");
    Ok(())
}

/// Reload the configuration when the process receives `SIGHUP`.
///
/// The handler lives for the whole server lifetime and exits when `shutdown`
/// fires. A failed reload is logged; the running configuration is kept.
#[cfg(unix)]
fn spawn_hangup_handler(
    reloader: reload::Reloader,
    mut hangup: tokio::signal::unix::Signal,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = hangup.recv() => {
                    info!("SIGHUP received; reloading configuration");
                    if let Err(error) = reloader.reload().await {
                        warn!(
                            %error,
                            "configuration reload failed; keeping the running configuration"
                        );
                    }
                }
            }
        }
    });
}

fn is_family_allowed(config: &Config, addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(_) => config.server.do_ip4,
        SocketAddr::V6(_) => config.server.do_ip6,
    }
}

/// Number of concurrent TCP/DoT connections to allow, or `None` when the
/// TCP-based listeners are disabled.
fn tcp_capacity(config: &Config) -> Option<usize> {
    if !config.server.do_tcp {
        return None;
    }
    let capacity = config
        .server
        .incoming_num_tcp
        .saturating_mul(config.server.num_threads.resolve());
    (capacity > 0).then_some(capacity)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dns_config::{Config, ThreadCount};
    use tokio_util::sync::CancellationToken;

    use super::{ServerError, serve, tcp_capacity};

    #[cfg(unix)]
    #[tokio::test]
    async fn unknown_username_fails_before_binding() {
        let mut config = Config::default();
        config.server.username = Some(format!("dns-rs-no-such-user-{}", std::process::id()));
        let error = serve(Arc::new(config), CancellationToken::new())
            .await
            .expect_err("an unknown user must fail startup");
        assert!(matches!(error, ServerError::Privilege(_)), "{error:?}");
    }

    #[test]
    fn tcp_capacity_is_per_thread_and_can_be_disabled() {
        let mut config = Config::default();
        config.server.num_threads = ThreadCount::Fixed(4);
        config.server.incoming_num_tcp = 8;
        assert_eq!(tcp_capacity(&config), Some(32));

        config.server.incoming_num_tcp = 0;
        assert_eq!(tcp_capacity(&config), None);

        config.server.incoming_num_tcp = 8;
        config.server.do_tcp = false;
        assert_eq!(tcp_capacity(&config), None);
    }
}
