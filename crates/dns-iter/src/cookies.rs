//! DNS COOKIE support (RFC 7873 / RFC 9018).
//!
//! Outgoing queries carry a client cookie bound to the upstream server
//! address. Responses that echo a different client cookie are rejected, which
//! makes off-path spoofing harder. If the upstream returns a server cookie we
//! remember it and include it in subsequent queries.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use dns_proto::{EDNS_COOKIE, Edns, EdnsOption};
use ring::hmac;

const COOKIE_OPTION_CODE: u16 = 10;
/// Total cookie length we send upstream: 8-byte client part + 8-byte server part.
const SERVER_COOKIE_LEN: usize = 8;

#[derive(Clone)]
pub struct CookieJar {
    key: Arc<hmac::Key>,
    server_cookies: Arc<Mutex<HashMap<SocketAddr, Vec<u8>>>>,
}

impl std::fmt::Debug for CookieJar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CookieJar").finish_non_exhaustive()
    }
}

impl CookieJar {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: Arc::new(hmac::Key::new(hmac::HMAC_SHA256, secret)),
            server_cookies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn mac(&self, data: &[u8]) -> [u8; 32] {
        let tag = hmac::sign(&self.key, data);
        let mut output = [0u8; 32];
        output.copy_from_slice(tag.as_ref());
        output
    }

    fn ip_bytes(address: IpAddr) -> Vec<u8> {
        match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        }
    }

    /// Deterministic client cookie for one upstream server.
    pub fn client_cookie(&self, server: SocketAddr) -> [u8; 8] {
        let mac = self.mac(&Self::ip_bytes(server.ip()));
        let mut cookie = [0u8; 8];
        cookie.copy_from_slice(&mac[..8]);
        cookie
    }

    /// Build the COOKIE option to include in an outgoing query.
    pub fn option_for(&self, server: SocketAddr) -> EdnsOption {
        let mut data = self.client_cookie(server).to_vec();
        if let Ok(cookies) = self.server_cookies.lock()
            && let Some(server_cookie) = cookies.get(&server)
        {
            data.extend_from_slice(server_cookie);
        }
        EdnsOption::Unknown(COOKIE_OPTION_CODE, data)
    }

    /// Validate the COOKIE option in an upstream response.
    ///
    /// Returns `false` when the response contains a cookie whose client part
    /// does not match ours, which means the packet did not answer our query.
    pub fn validate_response(&self, server: SocketAddr, edns: Option<&Edns>) -> bool {
        let Some(edns) = edns else {
            return true;
        };
        let Some(EdnsOption::Unknown(_, data)) = edns.option(EDNS_COOKIE) else {
            return true;
        };
        if data.len() < 8 || data.len() > 40 {
            return false;
        }
        if data[..8] != self.client_cookie(server) {
            return false;
        }
        if data.len() > 8
            && let Ok(mut cookies) = self.server_cookies.lock()
        {
            cookies.insert(server, data[8..].to_vec());
        }
        true
    }

    /// Produce a stateless server cookie for a downstream client.
    ///
    /// A request may carry just the 8-byte client cookie or the full
    /// client+server cookie echoed from a previous response. RFC 7873 section
    /// 5.2.2 requires the server to keep answering with a fresh server cookie
    /// in either case, so only the leading client cookie is significant.
    pub fn answer_cookie(&self, client: IpAddr, data: &[u8]) -> Option<Vec<u8>> {
        let client_cookie = data.get(..8)?;
        let mut input = Self::ip_bytes(client);
        input.extend_from_slice(client_cookie);
        let mac = self.mac(&input);
        let mut cookie = client_cookie.to_vec();
        cookie.extend_from_slice(&mac[..SERVER_COOKIE_LEN]);
        Some(cookie)
    }

    /// Verify a cookie echoed by a downstream client.
    pub fn verify_client_cookie(&self, client: IpAddr, data: &[u8]) -> bool {
        if data.len() != 8 + SERVER_COOKIE_LEN {
            return false;
        }
        let client_cookie = &data[..8];
        let mut input = Self::ip_bytes(client);
        input.extend_from_slice(client_cookie);
        let mac = self.mac(&input);
        data[8..] == mac[..SERVER_COOKIE_LEN]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use dns_proto::{EDNS_COOKIE, Edns, EdnsOption};

    use super::CookieJar;

    fn server() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53)
    }

    #[test]
    fn client_cookie_is_stable_and_server_bound() {
        let jar = CookieJar::new(b"test-secret");
        let first = jar.client_cookie(server());
        let second = jar.client_cookie(server());
        assert_eq!(first, second);

        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)), 53);
        assert_ne!(first, jar.client_cookie(other));
    }

    #[test]
    fn rejects_mismatched_client_cookie() {
        let jar = CookieJar::new(b"test-secret");
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0u8; 8]));
        assert!(!jar.validate_response(server(), Some(&edns)));
        assert!(edns.option(EDNS_COOKIE).is_some());
    }

    #[test]
    fn stores_server_cookie() {
        let jar = CookieJar::new(b"test-secret");
        let mut data = jar.client_cookie(server()).to_vec();
        data.extend_from_slice(&[7u8; 8]);
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Unknown(10, data));

        assert!(jar.validate_response(server(), Some(&edns)));
        let EdnsOption::Unknown(_, sent) = jar.option_for(server()) else {
            panic!("cookie option expected");
        };
        assert_eq!(sent.len(), 16);
    }

    #[test]
    fn downstream_cookie_round_trips() {
        let jar = CookieJar::new(b"test-secret");
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let client_cookie = [1u8; 8];
        let answer = jar.answer_cookie(client, &client_cookie).expect("cookie");
        assert!(jar.verify_client_cookie(client, &answer));

        let other_client = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!jar.verify_client_cookie(other_client, &answer));
    }

    #[test]
    fn echoed_client_and_server_cookie_is_renewed() {
        let jar = CookieJar::new(b"test-secret");
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let first = jar.answer_cookie(client, &[1u8; 8]).expect("cookie");
        assert_eq!(first.len(), 16);

        // A client that echoes the whole cookie must still receive a cookie.
        let second = jar
            .answer_cookie(client, &first)
            .expect("echoed cookie is renewed");
        assert_eq!(second.len(), 16);
        assert_eq!(&second[..8], &first[..8]);
        assert!(jar.verify_client_cookie(client, &second));

        // A bare client cookie that is too short is ignored.
        assert!(jar.answer_cookie(client, &[1u8; 4]).is_none());
    }
}
