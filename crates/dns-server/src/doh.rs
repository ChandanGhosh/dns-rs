//! DNS-over-HTTPS listener (RFC 8484).
//!
//! Supports `POST` with an `application/dns-message` body and `GET` with a
//! base64url-encoded `?dns=` parameter. HTTP/2 is preferred; HTTP/1.1 is
//! accepted as a fallback.

use std::convert::Infallible;
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::pipeline::{QueryPipeline, Transport};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_REQUEST: usize = 65_535;

/// Cancel upstream work when the HTTP request future is dropped.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    endpoint: String,
    pipeline: Arc<QueryPipeline>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, client)) => {
                        let acceptor = acceptor.clone();
                        let pipeline = Arc::clone(&pipeline);
                        let endpoint = endpoint.clone();
                        tokio::spawn(async move {
                            let stream = match tokio::time::timeout(
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
                                handle(request, Arc::clone(&pipeline), client, endpoint.clone())
                            });
                            let builder = Builder::new(TokioExecutor::new());
                            if let Err(error) = builder
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                            {
                                debug!(%client, %error, "DoH connection closed with an error");
                            }
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
    pipeline: Arc<QueryPipeline>,
    client: SocketAddr,
    endpoint: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match handle_inner(request, pipeline, client, &endpoint).await {
        Ok(response) => Ok(response),
        Err(status) => Ok(error_response(status)),
    }
}

async fn handle_inner(
    request: Request<Incoming>,
    pipeline: Arc<QueryPipeline>,
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
            if !content_type.starts_with(DNS_MESSAGE) {
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
            let decoded = decoded.strip_suffix(b"=").unwrap_or(&decoded);
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
    let _cancel_on_drop = CancelOnDrop(cancel.clone());
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
