//! Discovery of the default gateway used for built-in local namespaces.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Return the default gateways visible to this process.
///
/// Linux exposes the kernel routing table through `procfs`; other platforms
/// return no gateways, which makes local namespaces fail closed instead of
/// leaking a query to a public resolver.
pub fn default_gateways() -> Vec<IpAddr> {
    let mut gateways = Vec::with_capacity(2);
    if let Some(gateway) = ipv4_gateway() {
        gateways.push(gateway);
    }
    if let Some(gateway) = ipv6_gateway() {
        gateways.push(gateway);
    }
    gateways
}

fn ipv4_gateway() -> Option<IpAddr> {
    parse_ipv4_route_table(&fs::read_to_string("/proc/net/route").ok()?)
}

fn parse_ipv4_route_table(table: &str) -> Option<IpAddr> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let _interface = fields.next()?;
        let destination = fields.next()?;
        let gateway = fields.next()?;
        let _flags = fields.next()?;
        let _references = fields.next()?;
        let _uses = fields.next()?;
        let _metric = fields.next()?;
        let mask = fields.next()?;
        if destination != "00000000" || mask != "00000000" {
            return None;
        }
        let encoded = u32::from_str_radix(gateway, 16).ok()?;
        let address = Ipv4Addr::from(encoded.to_le_bytes());
        (address != Ipv4Addr::UNSPECIFIED).then_some(IpAddr::V4(address))
    })
}

fn ipv6_gateway() -> Option<IpAddr> {
    let table = fs::read_to_string("/proc/net/ipv6_route").ok()?;
    table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let destination = fields.next()?;
        let prefix = fields.next()?;
        let _source = fields.next()?;
        let _source_prefix = fields.next()?;
        let gateway = fields.next()?;
        if prefix != "00" || !destination.bytes().all(|byte| byte == b'0') {
            return None;
        }
        let address = Ipv6Addr::from(parse_ipv6_hex(gateway)?);
        (address != Ipv6Addr::UNSPECIFIED).then_some(IpAddr::V6(address))
    })
}

fn parse_ipv6_hex(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (digits, byte) in value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .zip(bytes.iter_mut())
    {
        let digits = std::str::from_utf8(digits).ok()?;
        *byte = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::{IpAddr, Ipv4Addr, Ipv6Addr, parse_ipv4_route_table, parse_ipv6_hex};

    #[test]
    fn parses_ipv4_default_gateway() {
        let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(
            parse_ipv4_route_table(table),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn parses_ipv6_gateway_hex() {
        let bytes = parse_ipv6_hex("fe800000000000000000000000000001").expect("gateway bytes");
        assert_eq!(IpAddr::V6(Ipv6Addr::from(bytes)).to_string(), "fe80::1");
        assert!(parse_ipv6_hex("fe80::1").is_none());
    }

    #[test]
    fn rejects_invalid_ipv6_gateway_hex() {
        assert!(parse_ipv6_hex("zz000000000000000000000000000001").is_none());
        assert!(parse_ipv6_hex("").is_none());
    }

    #[test]
    fn default_gateways_are_local_or_empty() {
        for gateway in super::default_gateways() {
            match gateway {
                IpAddr::V4(address) => assert_ne!(address, Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(address) => assert_ne!(address, Ipv6Addr::UNSPECIFIED),
            }
        }
    }
}
