//! The hosts, IP ranges and authserv-ids a caller trusts.
//!
//! A [`TrustSet`] is built once by the caller and passed to every parser that must decide
//! whether a header's claim can be believed. It never reads global state, so two calls with
//! different sets can run side by side.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A malformed IP range given to [`TrustSet::add_ip_range`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidIpRange {
    /// Byte offset into the range text where the fault starts: 0 for a malformed address,
    /// the first byte after `/` for a malformed or out-of-range prefix length.
    offset: usize,
}

impl InvalidIpRange {
    /// Byte offset into the range text where the fault starts: 0 for a malformed address,
    /// the first byte after `/` for a malformed or out-of-range prefix length.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for InvalidIpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IP range at byte {}", self.offset)
    }
}

impl Error for InvalidIpRange {}

/// The hosts or domains, IP ranges and authserv-ids a caller trusts.
///
/// An empty set trusts nothing. Entries are stored ASCII-lowercased at insert, so queries
/// compare in place without allocating and take time linear in the queried value.
#[derive(Debug, Clone, Default)]
pub struct TrustSet {
    /// Trusted authserv-ids, lowercased and never empty.
    authserv_ids: Vec<Box<str>>,
    /// Trusted domains, lowercased, without a trailing dot and never empty.
    hosts: Vec<Box<str>>,
    /// Trusted IPv4 networks as `(masked network, mask)`.
    v4_ranges: Vec<(u32, u32)>,
    /// Trusted IPv6 networks as `(masked network, mask)`.
    v6_ranges: Vec<(u128, u128)>,
}

impl TrustSet {
    /// Trusts results issued by `id`, matched exactly and ASCII case-insensitively; an empty
    /// id is ignored.
    pub fn add_authserv_id(&mut self, id: &str) -> &mut Self {
        if !id.is_empty() {
            self.authserv_ids.push(lowercase(id.as_bytes()));
        }
        self
    }

    /// Trusts `name` and every subdomain of it on a label boundary. The match is ASCII
    /// case-insensitive and ignores one trailing dot on either side. An empty name is
    /// ignored and trusts nothing.
    pub fn add_host(&mut self, name: &str) -> &mut Self {
        let trimmed = strip_trailing_dot(name.as_bytes());
        if !trimmed.is_empty() {
            self.hosts.push(lowercase(trimmed));
        }
        self
    }

    /// Trusts an address or a CIDR range such as `192.0.2.0/24` or `2001:db8::/32`; an
    /// address without a prefix length trusts exactly that address. Host bits below the
    /// prefix are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIpRange`] when the address does not parse (offset 0) or the prefix
    /// length is not a decimal number within 0 to 32 (IPv4) or 0 to 128 (IPv6); the offset
    /// is the first byte after the `/`.
    pub fn add_ip_range(&mut self, range: &str) -> Result<&mut Self, InvalidIpRange> {
        let (address, prefix) = match range.split_once('/') {
            Some((address, prefix)) => (address, Some((prefix, address.len().saturating_add(1)))),
            None => (range, None),
        };
        let ip: IpAddr = address
            .parse()
            .map_err(|_unparsable| InvalidIpRange { offset: 0 })?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let length = match prefix {
            Some((text, offset)) => parse_prefix(text, max, offset)?,
            None => max,
        };
        self.push_range(ip, length);
        Ok(self)
    }

    /// An empty set, which trusts nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores the masked network of `ip` with a prefix `length` already checked against its
    /// width; a mapped IPv6 range of at least 96 bits is stored as the IPv4 range it names.
    fn push_range(&mut self, ip: IpAddr, length: u8) {
        match ip {
            IpAddr::V4(addr) => self.push_v4(addr, length),
            IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
                Some(v4) if length >= 96 => self.push_v4(v4, length.saturating_sub(96)),
                _ => self.push_v6(addr, length),
            },
        }
    }

    /// Stores `addr` masked to its first `length` bits (at most 32).
    fn push_v4(&mut self, addr: Ipv4Addr, length: u8) {
        let mask = u32::MAX
            .checked_shr(u32::from(length))
            .map_or(u32::MAX, |host_bits| !host_bits);
        self.v4_ranges.push((u32::from(addr) & mask, mask));
    }

    /// Stores `addr` masked to its first `length` bits (at most 128).
    fn push_v6(&mut self, addr: Ipv6Addr, length: u8) {
        let mask = u128::MAX
            .checked_shr(u32::from(length))
            .map_or(u128::MAX, |host_bits| !host_bits);
        self.v6_ranges.push((u128::from(addr) & mask, mask));
    }

    /// Whether `id` is a trusted authserv-id, matched exactly and ASCII case-insensitively.
    #[must_use]
    pub fn trusts_authserv_id(&self, id: &[u8]) -> bool {
        self.authserv_ids
            .iter()
            .any(|entry| entry.as_bytes().eq_ignore_ascii_case(id))
    }

    /// Whether `host` is a trusted host or a subdomain of one, ignoring ASCII case and one
    /// trailing dot. `evil-example.com` is not a subdomain of `example.com`.
    #[must_use]
    pub fn trusts_host(&self, host: &[u8]) -> bool {
        let trimmed = strip_trailing_dot(host);
        self.hosts
            .iter()
            .any(|entry| is_same_or_subdomain(trimmed, entry.as_bytes()))
    }

    /// Whether `ip` lies inside a trusted range. An IPv4-mapped IPv6 address is also checked
    /// against the IPv4 ranges.
    #[must_use]
    pub fn trusts_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => self.trusts_v4(addr),
            IpAddr::V6(addr) => {
                let bits = u128::from(addr);
                self.v6_ranges.iter().any(|&(net, mask)| bits & mask == net)
                    || addr.to_ipv4_mapped().is_some_and(|v4| self.trusts_v4(v4))
            },
        }
    }

    /// Whether `addr` lies inside a trusted IPv4 range.
    fn trusts_v4(&self, addr: Ipv4Addr) -> bool {
        let bits = u32::from(addr);
        self.v4_ranges.iter().any(|&(net, mask)| bits & mask == net)
    }
}

/// `name` without one trailing dot, if it has one.
fn strip_trailing_dot(name: &[u8]) -> &[u8] {
    name.strip_suffix(b".").unwrap_or(name)
}

/// `bytes` as owned ASCII-lowercase text; invalid UTF-8 becomes U+FFFD, which no query matches.
fn lowercase(bytes: &[u8]) -> Box<str> {
    String::from_utf8_lossy(bytes).to_ascii_lowercase().into()
}

/// Whether `host` equals `entry` or ends with `.entry`, ignoring ASCII case.
fn is_same_or_subdomain(host: &[u8], entry: &[u8]) -> bool {
    let Some(split) = host.len().checked_sub(entry.len()) else {
        return false;
    };
    let (head, tail) = host.split_at(split);
    if !tail.eq_ignore_ascii_case(entry) {
        return false;
    }
    head.is_empty() || head.ends_with(b".")
}

/// The decimal prefix length in `text`, at most `max`; `offset` is where `text` starts in the
/// range for the error.
fn parse_prefix(text: &str, max: u8, offset: usize) -> Result<u8, InvalidIpRange> {
    let fault = InvalidIpRange { offset };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(fault);
    }
    match text.parse::<u8>() {
        Ok(length) if length <= max => Ok(length),
        _ => Err(fault),
    }
}

#[cfg(test)]
#[expect(
    unused_results,
    reason = "the builder methods return &mut Self for chaining, which tests ignore"
)]
mod tests {
    use std::net::IpAddr;

    use super::{InvalidIpRange, TrustSet};

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("fixture address parses")
    }

    fn with_range(range: &str) -> TrustSet {
        let mut set = TrustSet::new();
        set.add_ip_range(range).expect("fixture range is valid");
        set
    }

    #[test]
    fn a_host_entry_trusts_itself_and_subdomains_ignoring_case_and_one_trailing_dot() {
        let mut set = TrustSet::new();
        set.add_host("example.com");
        assert!(set.trusts_host(b"example.com"), "the name itself");
        assert!(
            set.trusts_host(b"mx.Example.COM."),
            "a subdomain with case and a dot"
        );
        assert!(set.trusts_host(b"a.b.example.com"), "a deeper subdomain");
    }

    #[test]
    fn a_host_entry_does_not_trust_lookalikes() {
        let mut set = TrustSet::new();
        set.add_host("Example.com.");
        assert!(!set.trusts_host(b"evil-example.com"), "no label boundary");
        assert!(
            !set.trusts_host(b"example.com.evil.net"),
            "entry is not the suffix"
        );
        assert!(
            !set.trusts_host(b"example.com.."),
            "only one trailing dot is ignored"
        );
        assert!(!set.trusts_host(b"com"), "a parent domain is not trusted");
        assert!(!set.trusts_host(b""), "an empty host is not trusted");
    }

    #[test]
    fn a_cidr_trusts_addresses_inside_and_not_outside() {
        let set = with_range("192.0.2.77/24");
        assert!(
            set.trusts_ip(ip("192.0.2.1")),
            "inside, host bits of the entry ignored"
        );
        assert!(!set.trusts_ip(ip("192.0.3.1")), "outside");
        let v6 = with_range("2001:db8::/32");
        assert!(v6.trusts_ip(ip("2001:db8:ffff::1")), "inside the v6 range");
        assert!(!v6.trusts_ip(ip("2001:db9::1")), "outside the v6 range");
    }

    #[test]
    fn a_bare_address_trusts_only_that_address_and_prefix_zero_trusts_the_family() {
        let set = with_range("192.0.2.1");
        assert!(set.trusts_ip(ip("192.0.2.1")), "the address");
        assert!(!set.trusts_ip(ip("192.0.2.2")), "its neighbour");
        let all_v4 = with_range("0.0.0.0/0");
        assert!(all_v4.trusts_ip(ip("203.0.113.9")), "any v4 address");
        assert!(
            !set.trusts_ip(ip("2001:db8::1")),
            "v6 is a different family"
        );
    }

    #[test]
    fn an_ipv4_mapped_address_matches_ipv4_ranges() {
        let set = with_range("192.0.2.0/24");
        assert!(set.trusts_ip(ip("::ffff:192.0.2.9")), "mapped inside");
        assert!(!set.trusts_ip(ip("::ffff:192.0.3.9")), "mapped outside");
        let mapped = with_range("::ffff:192.0.2.0/120");
        assert!(
            mapped.trusts_ip(ip("192.0.2.9")),
            "a mapped-range entry trusts the plain v4 form"
        );
    }

    #[test]
    fn malformed_ranges_are_rejected_with_the_offset_of_the_fault() {
        let mut set = TrustSet::new();
        let cases = [
            ("not-an-ip", 0),
            ("192.0.2.0/33", 10),
            ("2001:db8::/129", 11),
            ("192.0.2.0/", 10),
            ("192.0.2.0/+8", 10),
            ("192.0.2.0/999999999999", 10),
            ("192.0.2.0/-1", 10),
            ("", 0),
        ];
        for (text, offset) in cases {
            assert_eq!(
                set.add_ip_range(text).err(),
                Some(InvalidIpRange { offset }),
                "{text:?} is rejected at byte {offset}"
            );
        }
        assert!(
            !set.trusts_ip(ip("192.0.2.1")),
            "a rejected range adds nothing"
        );
    }

    #[test]
    fn an_authserv_id_matches_exactly_ignoring_case() {
        let mut set = TrustSet::new();
        set.add_authserv_id("MX.example.org");
        assert!(
            set.trusts_authserv_id(b"mx.EXAMPLE.org"),
            "same id, other case"
        );
        assert!(
            !set.trusts_authserv_id(b"a.mx.example.org"),
            "a subdomain is not the id"
        );
        assert!(
            !set.trusts_authserv_id(b"mx.example.org."),
            "no trailing-dot leniency"
        );
    }

    #[test]
    fn an_empty_set_trusts_nothing() {
        let set = TrustSet::new();
        assert!(!set.trusts_host(b"example.com"), "no hosts");
        assert!(!set.trusts_host(b""), "not even the empty host");
        assert!(!set.trusts_ip(ip("127.0.0.1")), "no ranges");
        assert!(
            !set.trusts_authserv_id(b""),
            "no ids, not even an empty one"
        );
        let mut blanks = TrustSet::new();
        blanks.add_host("").add_host(".").add_authserv_id("");
        assert!(!blanks.trusts_host(b""), "an empty host entry is ignored");
        assert!(
            !blanks.trusts_authserv_id(b""),
            "an empty id entry is ignored"
        );
    }

    #[test]
    fn non_utf8_query_bytes_do_not_panic_or_match() {
        let mut set = TrustSet::new();
        set.add_host("example.com").add_authserv_id("mx");
        assert!(
            !set.trusts_host(b"\xff.example.org"),
            "invalid bytes, other domain"
        );
        assert!(
            set.trusts_host(b"\xff.example.com"),
            "invalid bytes on a trusted domain"
        );
        assert!(
            !set.trusts_authserv_id(b"\xffx"),
            "invalid bytes are not an id"
        );
    }
}
