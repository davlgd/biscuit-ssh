//! IP networks in canonical form.
//!
//! Biscuit Datalog has no IP type, so network membership is expressed with
//! strings: the verifier provides one `source_net` fact per network enclosing
//! the client address, and tokens check for the networks they allow. This only
//! works if both sides spell a network the same way, hence [`Network`] always
//! clears host bits and uses the standard textual form of the address.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::Error;

/// An IP network with its host bits cleared, displayed as `addr/prefix`
/// (e.g. `10.0.0.0/8`, `2001:db8::/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// Builds the network of length `prefix` containing `addr`.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are treated as IPv4, so
    /// a client reaching a dual-stack listener is matched against IPv4
    /// networks: `::ffff:192.0.2.0/120` is `192.0.2.0/24`. A mapped network
    /// shorter than `/96` spans more than IPv4 and is refused.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, Error> {
        let (addr, prefix) = match addr {
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(_) if prefix < 96 => {
                    return Err(Error::invalid(
                        "network",
                        "IPv4-mapped networks need a prefix of at least 96",
                    ));
                }
                Some(v4) => (IpAddr::V4(v4), prefix - 96),
                None => (addr, prefix),
            },
            IpAddr::V4(_) => (addr, prefix),
        };
        if prefix > max_prefix(addr) {
            return Err(Error::invalid("network", "prefix is longer than the address"));
        }
        Ok(Self::masked(addr, prefix))
    }

    /// Returns every network containing `addr`, from `/0` to the host itself
    /// (`/32` or `/128`).
    pub fn enclosing(addr: IpAddr) -> impl Iterator<Item = Self> {
        let addr = addr.to_canonical();
        (0..=max_prefix(addr)).map(move |prefix| Self::masked(addr, prefix))
    }

    /// The host network (`/32` or `/128`) of `addr`.
    pub fn host(addr: IpAddr) -> Self {
        let addr = addr.to_canonical();
        Self::masked(addr, max_prefix(addr))
    }

    /// Clears the host bits of `addr`, which must already be canonical and
    /// have at least `prefix` bits.
    fn masked(addr: IpAddr, prefix: u8) -> Self {
        let addr = match addr {
            // The mask of a 32-bit width fits in a `u32`.
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from_bits(a.to_bits() & mask(prefix, 32) as u32)),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from_bits(a.to_bits() & mask(prefix, 128))),
        };
        Self { addr, prefix }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Network {
    type Err = Error;

    /// Parses `addr/prefix`; a bare address is read as a host network.
    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = || Error::invalid("network", "expected an address or addr/prefix");
        match s.split_once('/') {
            Some((addr, prefix)) => Self::new(
                addr.parse().map_err(|_| invalid())?,
                prefix.parse().map_err(|_| invalid())?,
            ),
            None => Ok(Self::host(s.parse().map_err(|_| invalid())?)),
        }
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

/// A mask with the `prefix` high bits set, over a `width`-bit address.
fn mask(prefix: u8, width: u32) -> u128 {
    match u32::from(prefix) {
        0 => 0,
        p => (u128::MAX << (128 - p)) >> (128 - width),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> String {
        s.parse::<Network>().unwrap().to_string()
    }

    #[test]
    fn canonicalizes_host_bits() {
        assert_eq!(net("10.1.2.3/8"), "10.0.0.0/8");
        assert_eq!(net("2001:db8:1::1/32"), "2001:db8::/32");
        assert_eq!(net("192.0.2.7"), "192.0.2.7/32");
        assert_eq!(net("0.0.0.0/0"), "0.0.0.0/0");
        assert_eq!(net("::ffff:192.0.2.7/120"), "192.0.2.0/24");
        assert_eq!(net("::ffff:192.0.2.7"), "192.0.2.7/32");
        assert_eq!(net("2001:db8::1"), "2001:db8::1/128");
    }

    #[test]
    fn rejects_invalid_networks() {
        for s in [
            "10.0.0.0/33",
            "::/129",
            "::ffff:192.0.2.7/24",
            "::ffff:192.0.2.7/129",
            "10.0.0/8",
            "10.0.0.0/",
            "host",
            "",
        ] {
            assert!(s.parse::<Network>().is_err(), "{s}");
        }
    }

    #[test]
    fn enumerates_enclosing_networks() {
        let v4: Vec<_> = Network::enclosing("192.0.2.7".parse().unwrap())
            .map(|n| n.to_string())
            .collect();
        assert_eq!(v4.len(), 33);
        assert_eq!(v4[0], "0.0.0.0/0");
        assert_eq!(v4[24], "192.0.2.0/24");
        assert_eq!(v4[32], "192.0.2.7/32");

        let mapped = Network::enclosing("::ffff:192.0.2.7".parse().unwrap()).count();
        assert_eq!(mapped, 33);
        assert_eq!(Network::enclosing("2001:db8::1".parse().unwrap()).count(), 129);
    }
}
