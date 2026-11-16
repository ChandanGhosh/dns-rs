//! DNS-over-HTTPS listener (RFC 8484).
//!
//! Supports `POST` with an `application/dns-message` body and `GET` with a
//! base64url-encoded `?dns=` parameter. HTTP/2 is preferred; HTTP/1.1 is
//! accepted as a fallback.

use std::mem::DropGuard;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use dns_cache::response_ttl;
use dns_proto::decode;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::pipeline::{PipelineHandle, Transport};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_REQUEST: usize = 65_535;

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    endpoint: String,
    pipeline: PipelineHandle,
    shutdown: CancellationToken,
    connections: Arc<Semaphore>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, client)) => {
                        if let Err(err) = stream.set_nodelay(true) {
                            warn!(%err, "failed to set TCP_NODELAY");
                        }
                        // Share the connection permit pool with the TCP and
                        // DoT listeners: without a cap, an idle-connection
                        // flood grows tasks, sockets, and TLS buffers
                        // unboundedly.
                        let permit = tokio::select! {
                            _ = shutdown.cancelled() => break,
                            permit = Arc::clone(&connections).acquire_owned() => {
                                match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                }
                            }
                        };
                        let acceptor = acceptor.clone();
                        let pipeline = pipeline.clone();
                        let endpoint = endpoint.clone();
                        tokio::spawn(async move {
                            // Held for the whole connection lifetime, like the
                            // TCP and DoT listeners. A timeout ensures that idle
                            // connections do not hold the connection permit
                            // indefinitely, which would starve other clients.
                            let _permit = tokio::time::timeout(
                                Duration::from_secs(30),
                                async {
                                    let _permit = permit;
                                    let stream: tokio_rustls::server::TlsStream<TcpStream> =
                                        match tokio::time::timeout(
                                            Duration::from_secs(10),
                                            acceptor.accept(stream),
                                        )
                                        .await
                                        {
                                            Ok(Ok(stream)) => stream,
                                            Ok(Err(error)) => {
                                                debug!(%client, %error, "DoH handshake failed");
                                                return;
                                            }
                                            Err(_) => {
                                                debug!(%client, "DoH handshake timed out");
                                                return;
                                            }
                                        };

                                    let service = service_fn(move |request| {
                                        handle(request, pipeline.clone(), client, endpoint.clone())
                                    });
                                    let mut builder = Builder::new(TokioExecutor::new());
                                    // Without a timer, hyper enforces no header-read or
                                    // keep-alive deadlines and an idle connection lives
                                    // forever. The 10s handshake timeout above only
                                    // covers the TLS setup.
                                    builder.http1().timer(TokioTimer::new());
                                    builder.http2().timer(TokioTimer::new());
                                    if let Err(error) = builder
                                        .serve_connection(TokioIo::new(stream), service)
                                        .await
                                    {
                                        debug!(%client, %error, "DoH connection closed with an error");
                                    }
                                },
                            )
                            .await;
                            // If the timeout expires, the task ends and the
                            // permit is released back to the semaphore pool.
                        });
                    }
                    Err(error) => {
                        debug!(%error, "DoH accept error");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle(
    request: Request<Incoming>,
    pipeline: PipelineHandle,
    client: SocketAddr,
    endpoint: String,
) -> Result<Response<Full<Bytes>>, !> {
    match handle_inner(request, pipeline, client, &endpoint).await {
        Ok(response) => Ok(response),
        Err(status) => Ok(error_response(status)),
    }
}

async fn handle_inner(
    request: Request<Incoming>,
    pipeline: PipelineHandle,
    client: SocketAddr,
    endpoint: &str,
) -> Result<Response<Full<Bytes>>, StatusCode> {
    if request.uri().path() != endpoint {
        return Err(StatusCode::NOT_FOUND);
    }

    let query = match *request.method() {
        Method::POST => {
            let content_type = request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !is_dns_message(content_type) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            Limited::new(request.into_body(), MAX_REQUEST)
                .collect()
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?
                .to_bytes()
                .to_vec()
        }
        Method::GET => {
            let encoded = request
                .uri()
                .query()
                .and_then(|query| {
                    query.split('&').find_map(|pair| {
                        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                        (key == "dns").then_some(value)
                    })
                })
                .ok_or(StatusCode::BAD_REQUEST)?;
            let decoded = percent_decode(encoded);
            let decoded = decoded.trim_suffix(b"=");
            BASE64URL_NOPAD
                .decode(decoded)
                .map_err(|_| StatusCode::BAD_REQUEST)?
        }
        _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    if query.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let cancel = CancellationToken::new();
    let _cancel_on_drop = DropGuard::new(cancel.clone(), |token| token.cancel());
    let response = pipeline
        .handle_with_cancel(&query, client, Transport::Https, cancel)
        .await
        .ok_or(StatusCode::FORBIDDEN)?;

    let max_age = decode(&response)
        .ok()
        .map(|message| response_ttl(&message, 0, 86_400).as_secs())
        .unwrap_or(0);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(CACHE_CONTROL, format!("max-age={max_age}"))
        .body(Full::new(Bytes::from(response)))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response
            .headers_mut()
            .insert(ALLOW, "GET, POST".parse().expect("static header value"));
    }
    response
}

fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).and_then(|byte| hex(*byte)),
                bytes.get(index + 2).and_then(|byte| hex(*byte)),
            )
        {
            output.push(high * 16 + low);
            index += 3;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    output
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Whether a `Content-Type` value names the DNS wire-format media type.
///
/// Parameters after `;` are ignored and the media type compares
/// case-insensitively, but the type and subtype must match exactly so a value
/// such as `application/dns-message-extra` is rejected.
fn is_dns_message(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(DNS_MESSAGE))
}

#[cfg(test)]
mod tests {
    use super::is_dns_message;

    #[test]
    fn accepts_only_the_dns_message_media_type() {
        assert!(is_dns_message("application/dns-message"));
        assert!(is_dns_message("application/dns-message; charset=utf-8"));
        assert!(is_dns_message("Application/DNS-Message"));
        assert!(!is_dns_message("application/dns-message-extra"));
        assert!(!is_dns_message("application/octet-stream"));
        assert!(!is_dns_message(""));
    }
}
