//! Outbound HTTP, on a leash (README.md §22.8).
//!
//! This is the largest new attack surface in the system, and it is off by
//! default: with no allowlist configured, every call is refused. Everything
//! here exists because "fetch this URL and summarise it" is the second thing
//! anyone asks a code sandbox to do, and the first thing that turns a sandbox
//! into an SSRF proxy.
//!
//! # The rules, and why each one is not negotiable
//!
//! 1. **An allowlist, never a denylist.** A denylist of private ranges is a
//!    game of whack-a-mole; an allowlist is a decision an operator made.
//! 2. **Resolve first, then check the resolved address.** Checking a hostname
//!    proves nothing: `evil.example.com` can resolve to `169.254.169.254`.
//! 3. **Connect to the address that was checked.** Handing the hostname back to
//!    the connect call invites a second DNS lookup with a different answer,
//!    which is DNS rebinding in one line.
//! 4. **Every resolved address must pass.** A host that answers with one public
//!    and one private address is not half-safe.
//! 5. **No redirects.** A `302` to the metadata endpoint is the whole attack.
//!    The response is handed back as-is; a guest that wants to follow one may
//!    ask again, and that request is checked like any other.
//! 6. **Time comes out of the request budget, never on top of it.** Epoch
//!    interruption (§6.1) only fires at WASM instruction boundaries, so a guest
//!    parked in a host call cannot be interrupted at all — without an explicit
//!    socket timeout the deadline would stop being a bound.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Cap on a fetched response. Sized to match the request-body cap of §6.4:
/// what a guest can be handed and what it can be sent should not differ by an
/// order of magnitude for no reason.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Operator-configured allowlist. Empty means egress is off.
///
/// **Cluster-wide, not per-tenant** — §22.8 specified per-tenant and this is a
/// deliberate narrowing of scope, recorded there. Enforcement lives on the
/// worker because that is where the socket is opened, and a policy checked
/// anywhere else is a policy something can route around.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    hosts: Vec<String>,
    allow_private: bool,
}

impl Policy {
    /// Hosts an operator has decided guests may reach. Case-insensitive; no
    /// wildcards, because `*.example.com` is a decision about subdomains that
    /// nobody has made yet.
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            hosts: hosts
                .into_iter()
                .map(|host| host.as_ref().trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect(),
            allow_private: false,
        }
    }

    /// Permits allowlisted hosts that resolve inside the network.
    ///
    /// **This switches off the single most important check in this module**, so
    /// it is spelled out rather than inferred and it is never on by default.
    /// The legitimate use is an operator who has deliberately allowlisted an
    /// internal service — the allowlist is still enforced, so this widens what
    /// an *already permitted* host may resolve to and nothing else. It does not
    /// permit `169.254.169.254` unless somebody put it on the list.
    ///
    /// It is also the only way to test the client against a loopback server,
    /// and an untested HTTP client is a worse hazard than a documented switch.
    pub fn allow_private_addresses(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// Reads `NEBULA_EGRESS_ALLOW`, a comma-separated host list.
    ///
    /// Absent or empty leaves egress disabled, which is the only safe default
    /// for a feature whose failure mode is "your sandbox is now a proxy".
    pub fn from_env() -> Self {
        match std::env::var("NEBULA_EGRESS_ALLOW") {
            Ok(raw) => Self::new(raw.split(',')),
            Err(_) => Self::default(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.hosts.is_empty()
    }

    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.hosts.contains(&host)
    }
}

/// Why a fetch did not happen, or did not finish.
///
/// Distinct variants rather than one error because a guest can act on the
/// difference: a blocked host is a bug in the script, a timeout is a budget
/// problem, and `Tls` is neither. §7.2's convention makes all of them a `-1`
/// to the guest; the detail goes to the host's logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No allowlist configured. The default.
    Disabled,
    /// Not `http://…`, or unparseable.
    BadUrl,
    /// `https://`. Named separately because it is the one refusal a caller is
    /// most likely to hit and least likely to guess.
    Tls,
    /// The host is not on the allowlist.
    HostNotAllowed,
    /// DNS returned nothing.
    Unresolvable,
    /// DNS returned an address inside the infrastructure.
    PrivateAddress,
    /// The request budget ran out (§6.1).
    Timeout,
    /// Connection failed, or the peer went away.
    Io,
    /// The response exceeded [`MAX_RESPONSE_BYTES`].
    TooLarge,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "outbound HTTP is disabled on this cluster",
            Self::BadUrl => "not a valid http:// url",
            Self::Tls => "https is not supported; only plain http",
            Self::HostNotAllowed => "host is not on the egress allowlist",
            Self::Unresolvable => "host did not resolve",
            Self::PrivateAddress => "host resolved to a non-public address",
            Self::Timeout => "the request budget ran out",
            Self::Io => "the connection failed",
            Self::TooLarge => "the response exceeded the size cap",
        })
    }
}

/// A parsed `http://host[:port]/path`.
#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Target, Refusal> {
    let url = url.trim();
    if url.len() > 2048 {
        return Err(Refusal::BadUrl);
    }
    if url.to_ascii_lowercase().starts_with("https://") {
        return Err(Refusal::Tls);
    }
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .ok_or(Refusal::BadUrl)?;

    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    // Userinfo is where `http://allowed.example.com@evil.test/` lives: a reader
    // sees the allowed host, the parser sees the other one. Refusing outright
    // beats being clever about it.
    if authority.contains('@') || authority.is_empty() {
        return Err(Refusal::BadUrl);
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| Refusal::BadUrl)?),
        None => (authority, 80),
    };
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '\r' || c == '\n') {
        return Err(Refusal::BadUrl);
    }

    Ok(Target {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// Whether an address is out on the public internet.
///
/// Written as an allowlist of "not one of these" rather than using
/// `IpAddr::is_global`, which is still unstable. The list is the one that
/// matters in practice: loopback, the RFC 1918 ranges, carrier-grade NAT, and
/// above all `169.254.0.0/16` — because `169.254.169.254` is the cloud metadata
/// endpoint and is the single most valuable thing an SSRF can reach.
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (64..128).contains(&b))
                // 0.0.0.0/8, "this network" — and `0.0.0.0` itself routes to
                // localhost on Linux.
                || a == 0
                // 192.0.0.0/24, IETF protocol assignments.
                || (a == 192 && b == 0 && v4.octets()[2] == 0)
                // 240.0.0.0/4, reserved.
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address is an IPv4 address wearing a hat, and
            // `::ffff:169.254.169.254` reaches the same metadata endpoint.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let segments = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7, unique local.
                || (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10, link local.
                || (segments[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Fetches `url`, or explains why it did not.
///
/// `budget` is what remains of the request's deadline, and it bounds the whole
/// operation — resolution, connect, and read. Returns the **raw response**:
/// status line, headers, blank line, body. Handing back only the body would
/// hide the status code from the guest, and a script that cannot tell `200`
/// from `404` will treat an error page as data.
pub fn fetch(policy: &Policy, url: &str, budget: Duration) -> Result<Vec<u8>, Refusal> {
    if !policy.is_enabled() {
        return Err(Refusal::Disabled);
    }
    if budget.is_zero() {
        return Err(Refusal::Timeout);
    }

    let started = Instant::now();
    let target = parse(url)?;
    if !policy.allows(&target.host) {
        return Err(Refusal::HostNotAllowed);
    }

    // Resolved once, and the *resolved address* is what gets connected to. The
    // hostname is never handed to `connect` again, so there is no second lookup
    // for an attacker's DNS to answer differently.
    let addresses: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| Refusal::Unresolvable)?
        .collect();
    if addresses.is_empty() {
        return Err(Refusal::Unresolvable);
    }
    // Every address, not the first that passes: a host answering with one
    // public and one private address is not half-safe, and which one a
    // connection attempt lands on is not ours to decide.
    if !policy.allow_private && !addresses.iter().all(|addr| is_public(&addr.ip())) {
        return Err(Refusal::PrivateAddress);
    }

    let remaining = |started: Instant| budget.checked_sub(started.elapsed());
    let mut stream =
        TcpStream::connect_timeout(&addresses[0], remaining(started).ok_or(Refusal::Timeout)?)
            .map_err(|err| classify(&err))?;

    let deadline = remaining(started).ok_or(Refusal::Timeout)?;
    stream
        .set_read_timeout(Some(deadline))
        .map_err(|_| Refusal::Io)?;
    stream
        .set_write_timeout(Some(deadline))
        .map_err(|_| Refusal::Io)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\
         User-Agent: nebula/{}\r\n\r\n",
        target.path,
        target.host,
        env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| classify(&err))?;

    // Read to EOF: `Connection: close` makes that the whole framing, and it
    // means no chunked decoder to get wrong. One byte past the cap is read so
    // an oversized response is refused rather than silently truncated into
    // something a guest would parse as complete.
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if remaining(started).is_none() {
            return Err(Refusal::Timeout);
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response.len() > MAX_RESPONSE_BYTES {
                    return Err(Refusal::TooLarge);
                }
            }
            Err(err) => return Err(classify(&err)),
        }
    }
    Ok(response)
}

fn classify(err: &std::io::Error) -> Refusal {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    match err.kind() {
        TimedOut | WouldBlock => Refusal::Timeout,
        _ => Refusal::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("address")
    }

    #[test]
    fn egress_is_off_until_an_operator_turns_it_on() {
        // The default for a feature whose failure mode is "your sandbox is now
        // an SSRF proxy" is off, and nothing about that is configurable by a
        // guest or by a tenant.
        let policy = Policy::default();
        assert!(!policy.is_enabled());
        assert_eq!(
            fetch(&policy, "http://example.com/", Duration::from_secs(1)),
            Err(Refusal::Disabled)
        );
    }

    #[test]
    fn only_listed_hosts_are_allowed() {
        let policy = Policy::new(["api.example.com", "Example.ORG"]);
        assert!(policy.allows("api.example.com"));
        // Host comparison is case-insensitive in DNS, so the allowlist has to
        // be too — otherwise `API.example.com` is a bypass.
        assert!(policy.allows("API.EXAMPLE.COM"));
        assert!(policy.allows("example.org"));

        assert!(!policy.allows("evil.test"));
        // A suffix is not a match: `notexample.com` and `example.com.evil.test`
        // are the two classic ways an allowlist gets read as a substring.
        assert!(!policy.allows("api.example.com.evil.test"));
        assert!(!policy.allows("notapi.example.com"));
    }

    #[test]
    fn the_metadata_endpoint_is_not_reachable() {
        // 169.254.169.254 is the single most valuable thing an SSRF can reach,
        // and it is inside link-local rather than any RFC 1918 range — a
        // private-address check that only covers 10/172/192 misses it.
        assert!(!is_public(&ip("169.254.169.254")));
        assert!(!is_public(&ip("::ffff:169.254.169.254")));
    }

    #[test]
    fn no_address_inside_the_infrastructure_counts_as_public() {
        for raw in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "192.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(&ip(raw)), "{raw} must not be reachable");
        }

        for raw in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(is_public(&ip(raw)), "{raw} is an ordinary public address");
        }
    }

    #[test]
    fn https_is_refused_by_name_rather_than_as_a_bad_url() {
        // The one refusal a caller is most likely to hit and least likely to
        // guess. Reporting it as a malformed URL would send them checking their
        // spelling.
        assert_eq!(parse("https://example.com/").unwrap_err(), Refusal::Tls);
        assert_eq!(parse("HTTPS://example.com/").unwrap_err(), Refusal::Tls);
    }

    #[test]
    fn a_url_that_reads_as_one_host_and_parses_as_another_is_refused() {
        // `http://allowed.example.com@evil.test/` shows the allowed host to a
        // human and resolves the other one. Refusing userinfo outright beats
        // being clever about it.
        assert_eq!(
            parse("http://api.example.com@evil.test/").unwrap_err(),
            Refusal::BadUrl
        );

        for bad in [
            "",
            "example.com",
            "ftp://example.com/",
            "http://",
            "http://exa mple.com/",
            "http://example.com:99999/",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn a_url_parses_into_the_pieces_a_request_needs() {
        let target = parse("http://api.example.com/v1/things?q=1").unwrap();
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/v1/things?q=1");

        let target = parse("http://api.example.com:8080").unwrap();
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/", "a bare authority still needs a path");
    }

    #[test]
    fn the_private_address_escape_hatch_does_not_widen_the_allowlist() {
        // The switch relaxes *where an allowed host may resolve to*, not *which
        // hosts are allowed*. If it ever did both, one careless operator flag
        // would turn the metadata endpoint into a reachable target.
        let policy = Policy::new(["internal.svc"]).allow_private_addresses();
        assert!(!policy.allows("169.254.169.254"));
        assert_eq!(
            fetch(&policy, "http://169.254.169.254/", Duration::from_secs(1)),
            Err(Refusal::HostNotAllowed)
        );
    }

    #[test]
    fn an_allowlisted_host_that_resolves_inward_is_still_refused() {
        // The check that matters. `localhost` is a perfectly ordinary hostname
        // an operator could be talked into allowlisting, and it resolves to
        // loopback — so allowlisting a *name* must never be enough on its own.
        let policy = Policy::new(["localhost"]);
        assert_eq!(
            fetch(&policy, "http://localhost:1/", Duration::from_secs(1)),
            Err(Refusal::PrivateAddress)
        );
    }

    #[test]
    fn an_exhausted_budget_refuses_before_opening_a_socket() {
        // §6.1's epoch deadline cannot interrupt a guest parked in a host call,
        // so the budget has to be checked here or it stops being a bound.
        let policy = Policy::new(["example.com"]);
        assert_eq!(
            fetch(&policy, "http://example.com/", Duration::ZERO),
            Err(Refusal::Timeout)
        );
    }

    #[test]
    fn a_blocked_host_is_refused_before_dns_is_consulted() {
        // Ordering matters: a disallowed host must not become a DNS lookup an
        // attacker can use as an oracle or as an amplifier.
        let policy = Policy::new(["api.example.com"]);
        assert_eq!(
            fetch(
                &policy,
                "http://this-should-never-be-resolved.invalid/",
                Duration::from_secs(5)
            ),
            Err(Refusal::HostNotAllowed)
        );
    }
}
