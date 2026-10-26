use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Built-in root server hints (all 13 root server identities).
///
/// These are only a bootstrap: the first iterative query primes the root NS
/// set and replaces this list with the learned addresses and glue.
pub fn root_hints() -> Vec<SocketAddr> {
    let roots: [([u8; 4], [u16; 8]); 13] = [
        ([198, 41, 0, 4], [0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30]), // a
        ([170, 247, 170, 2], [0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb]),   // b
        ([192, 33, 4, 12], [0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc]),      // c
        ([199, 7, 91, 13], [0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd]),     // d
        ([192, 203, 230, 10], [0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe]),  // e
        ([192, 5, 5, 241], [0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf]),     // f
        ([192, 112, 36, 4], [0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d]),  // g
        ([198, 97, 190, 53], [0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53]),   // h
        ([192, 36, 148, 17], [0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53]),     // i
        (
            [192, 58, 128, 30],
            [0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30],
        ), // j
        ([193, 0, 14, 129], [0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1]),       // k
        ([199, 7, 83, 42], [0x2001, 0x500, 0x3, 0, 0, 0, 0, 0x42]),     // l
        ([202, 12, 27, 33], [0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35]),      // m
    ];

    let mut hints = Vec::with_capacity(roots.len() * 2);
    for (v4, v6) in roots {
        hints.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), 53));
        hints.push(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7],
            )),
            53,
        ));
    }
    hints
}
