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
//! 1. **A per-tenant allowlist, never a denylist.** A denylist of private
//!    ranges is a game of whack-a-mole; an allowlist is a decision an operator
//!    made. The tenant comes from the bearer token the gateway established
//!    (§13), never from anything the guest can set.
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

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// Cap on a fetched response. Sized to match the request-body cap of §6.4:
/// what a guest can be handed and what it can be sent should not differ by an
/// order of magnitude for no reason.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Operator-configured allowlist, per tenant. Empty means egress is off.
///
/// **Both the policy and its enforcement live on the worker**, and that is the
/// point. The worker is the process that opens the socket, so a policy checked
/// anywhere else is one something can route around — and a policy *sent* to the
/// worker in a request would be a policy the request could influence. This one
/// is local configuration, and nothing on the wire can change it.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Hosts every tenant may reach.
    shared: Vec<String>,
    /// Hosts a named tenant may reach, *instead of* the shared list.
    per_tenant: HashMap<String, Vec<String>>,
    allow_private: bool,
}

fn normalise<I, S>(hosts: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    hosts
        .into_iter()
        .map(|host| host.as_ref().trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

impl Policy {
    /// Hosts every tenant may reach. Case-insensitive; no wildcards, because
    /// `*.example.com` is a decision about subdomains that nobody has made yet.
    ///
    /// A shared list is a deliberate grant to everyone. Where tenants should not
    /// share a destination, name them with [`Policy::for_tenant`].
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            shared: normalise(hosts),
            per_tenant: HashMap::new(),
            allow_private: false,
        }
    }

    /// Hosts one tenant may reach, **replacing** the shared list for it rather
    /// than adding to it.
    ///
    /// Replacement rather than union so that reading the configuration answers
    /// "what can this tenant reach" in one line. A union would mean the answer
    /// is always two lines and the shared list can never be narrowed for
    /// anyone — which is the case an operator most often wants.
    pub fn for_tenant<I, S>(mut self, tenant: &str, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.per_tenant
            .insert(tenant.trim().to_string(), normalise(hosts));
        self
    }

    fn hosts_for(&self, tenant: &str) -> &[String] {
        self.per_tenant
            .get(tenant.trim())
            .map(Vec::as_slice)
            .unwrap_or(&self.shared)
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

    /// Reads `NEBULA_EGRESS_ALLOW`.
    ///
    /// Semicolons separate groups; a group is either a bare comma-separated host
    /// list (shared by every tenant) or `tenant=host,host`:
    ///
    /// ```text
    /// NEBULA_EGRESS_ALLOW="status.example.com;acme=api.example.com,cdn.example.com"
    /// ```
    ///
    /// Absent or empty leaves egress disabled, which is the only safe default
    /// for a feature whose failure mode is "your sandbox is now a proxy".
    pub fn from_env() -> Self {
        match std::env::var("NEBULA_EGRESS_ALLOW") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::default(),
        }
    }

    pub fn parse(raw: &str) -> Self {
        let mut policy = Self::default();
        for group in raw.split(';').map(str::trim).filter(|g| !g.is_empty()) {
            match group.split_once('=') {
                Some((tenant, hosts)) => {
                    policy = policy.for_tenant(tenant, hosts.split(','));
                }
                // A bare list grants every tenant. Kept because it is the
                // obvious thing to write and it is what a single-tenant
                // deployment wants; it is a grant to everyone and the
                // documentation says so.
                None => policy.shared = normalise(group.split(',')),
            }
        }
        policy
    }

    /// Whether any tenant can reach anything at all.
    pub fn is_enabled(&self) -> bool {
        !self.shared.is_empty() || self.per_tenant.values().any(|hosts| !hosts.is_empty())
    }

    pub fn allows(&self, tenant: &str, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.hosts_for(tenant).contains(&host)
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
    /// The TLS handshake failed — an untrusted certificate, a name mismatch, or
    /// a peer that does not speak TLS on that port. Named separately because it
    /// is the one failure a caller can usually fix.
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
            Self::Tls => "the TLS handshake failed",
            Self::HostNotAllowed => "host is not on the egress allowlist",
            Self::Unresolvable => "host did not resolve",
            Self::PrivateAddress => "host resolved to a non-public address",
            Self::Timeout => "the request budget ran out",
            Self::Io => "the connection failed",
            Self::TooLarge => "the response exceeded the size cap",
        })
    }
}

/// A parsed `http[s]://host[:port]/path`.
#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
    path: String,
    tls: bool,
}

fn parse(url: &str) -> Result<Target, Refusal> {
    let url = url.trim();
    if url.len() > 2048 {
        return Err(Refusal::BadUrl);
    }
    let lower = url.to_ascii_lowercase();
    let (rest, tls, default_port) = if let Some(rest) = lower.strip_prefix("https://") {
        (&url[url.len() - rest.len()..], true, 443)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (&url[url.len() - rest.len()..], false, 80)
    } else {
        return Err(Refusal::BadUrl);
    };

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
        None => (authority, default_port),
    };
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '\r' || c == '\n') {
        return Err(Refusal::BadUrl);
    }

    Ok(Target {
        host: host.to_string(),
        port,
        path: path.to_string(),
        tls,
    })
}

/// One client config for the process.
///
/// Roots come from `webpki-roots` rather than the platform store: a container
/// with no `ca-certificates` package installed would otherwise fail every
/// handshake with an error that looks like the remote's fault. Built once —
/// parsing a few hundred certificates per request would dwarf the request.
fn tls_config() -> Result<Arc<ClientConfig>, Refusal> {
    static CONFIG: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();

    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Some(Arc::new(config))
        })
        .clone()
        .ok_or(Refusal::Tls)
}

/// A socket, with or without TLS on top.
///
/// Boxed on the TLS side because a `ClientConnection` carries buffers, and an
/// enum sized for the larger variant would make every plain HTTP fetch pay for
/// TLS it is not using.
enum Transport {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
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
pub fn fetch(
    policy: &Policy,
    tenant: &str,
    url: &str,
    budget: Duration,
) -> Result<Vec<u8>, Refusal> {
    if !policy.is_enabled() {
        return Err(Refusal::Disabled);
    }
    if budget.is_zero() {
        return Err(Refusal::Timeout);
    }

    let started = Instant::now();
    let target = parse(url)?;
    if !policy.allows(tenant, &target.host) {
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

    // The certificate is verified against the **hostname**, never against the
    // address that was connected to. Those are deliberately different: the
    // address check (above) decides whether the endpoint is somewhere we are
    // willing to talk to, and the certificate decides whether it is who it
    // claims to be. Verifying against the IP would fail every ordinary site and
    // teach whoever debugged it to turn verification off.
    let mut stream = if target.tls {
        let name = ServerName::try_from(target.host.clone()).map_err(|_| Refusal::BadUrl)?;
        let mut connection =
            ClientConnection::new(tls_config()?, name).map_err(|_| Refusal::Tls)?;
        // Handshake eagerly. `StreamOwned` would do it lazily on first write and
        // report a bad certificate as a generic I/O error, which is the one
        // failure a caller can usually fix and so the one worth naming.
        connection
            .complete_io(&mut stream)
            .map_err(|_| Refusal::Tls)?;
        Transport::Tls(Box::new(StreamOwned::new(connection, stream)))
    } else {
        Transport::Plain(stream)
    };

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
            fetch(&policy, "t", "http://example.com/", Duration::from_secs(1)),
            Err(Refusal::Disabled)
        );
    }

    #[test]
    fn only_listed_hosts_are_allowed() {
        let policy = Policy::new(["api.example.com", "Example.ORG"]);
        assert!(policy.allows("acme", "api.example.com"));
        // Host comparison is case-insensitive in DNS, so the allowlist has to
        // be too — otherwise `API.example.com` is a bypass.
        assert!(policy.allows("acme", "API.EXAMPLE.COM"));
        assert!(policy.allows("acme", "example.org"));

        assert!(!policy.allows("acme", "evil.test"));
        // A suffix is not a match: `notexample.com` and `example.com.evil.test`
        // are the two classic ways an allowlist gets read as a substring.
        assert!(!policy.allows("acme", "api.example.com.evil.test"));
        assert!(!policy.allows("acme", "notapi.example.com"));
    }

    #[test]
    fn one_tenants_allowlist_is_not_anothers() {
        let policy = Policy::new(["shared.example.com"])
            .for_tenant("acme", ["acme-api.example.com"])
            .for_tenant("globex", ["globex-api.example.com"]);

        assert!(policy.allows("acme", "acme-api.example.com"));
        assert!(!policy.allows("acme", "globex-api.example.com"));
        assert!(!policy.allows("globex", "acme-api.example.com"));

        // A named tenant gets its own list *instead of* the shared one, so a
        // grant can be narrowed for one tenant without being narrowed for all.
        assert!(!policy.allows("acme", "shared.example.com"));
        // An unnamed tenant falls back to the shared list.
        assert!(policy.allows("someone-else", "shared.example.com"));
    }

    #[test]
    fn the_env_format_parses_both_shapes() {
        let policy = Policy::parse("status.example.com;acme=api.example.com,cdn.example.com");

        assert!(policy.is_enabled());
        assert!(policy.allows("anyone", "status.example.com"));
        assert!(policy.allows("acme", "api.example.com"));
        assert!(policy.allows("acme", "cdn.example.com"));
        assert!(!policy.allows("acme", "status.example.com"));

        // Whitespace is what a real config file has in it.
        let policy = Policy::parse("  acme = api.example.com , cdn.example.com  ");
        assert!(policy.allows("acme", "api.example.com"));
        assert!(policy.allows("acme", "cdn.example.com"));

        // Empty, blank, and separator-only values must all leave egress off
        // rather than producing a policy that allows an empty host name.
        for raw in ["", "   ", ";", ",", ";;", "=", "acme="] {
            assert!(!Policy::parse(raw).is_enabled(), "{raw:?} enabled egress");
        }
    }

    #[test]
    fn a_tenant_with_an_empty_list_reaches_nothing_rather_than_everything() {
        // The dangerous reading of "no entry for this tenant" is "no
        // restrictions". An explicitly empty list must mean explicitly nothing,
        // and it must not fall back to the shared grant.
        let policy =
            Policy::new(["shared.example.com"]).for_tenant("locked-down", Vec::<&str>::new());
        assert!(!policy.allows("locked-down", "shared.example.com"));
        assert!(!policy.allows("locked-down", "anything.example.com"));
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
    fn https_parses_and_defaults_to_the_right_port() {
        let target = parse("https://api.example.com/v1").unwrap();
        assert!(target.tls);
        assert_eq!(target.port, 443);
        assert_eq!(target.host, "api.example.com");

        // Scheme matching is case-insensitive, but the *host* must survive with
        // its original case for certificate verification to see what the caller
        // wrote.
        let target = parse("HTTPS://API.example.com/").unwrap();
        assert!(target.tls);
        assert_eq!(target.host, "API.example.com");

        // An explicit port still wins over the scheme default.
        assert_eq!(parse("https://api.example.com:8443/").unwrap().port, 8443);
        assert_eq!(parse("http://api.example.com/").unwrap().port, 80);
    }

    /// A peer that speaks plain HTTP on the port must not be mistaken for TLS.
    ///
    /// Self-contained, and it is the test that proves the handshake actually
    /// runs: without `complete_io` the failure would surface much later as a
    /// generic read error, and `Refusal::Tls` would be unreachable.
    #[test]
    fn a_failed_handshake_is_reported_as_tls_rather_than_as_io() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK

not tls at all",
                );
            }
        });

        let policy = Policy::new(["127.0.0.1"]).allow_private_addresses();
        assert_eq!(
            fetch(
                &policy,
                "t",
                &format!("https://127.0.0.1:{port}/"),
                Duration::from_secs(5)
            ),
            Err(Refusal::Tls)
        );
    }

    /// The only test here that touches the real internet, and it skips rather
    /// than fails without it.
    ///
    /// It earns that: nothing else proves the root store, the handshake, and
    /// certificate verification work *together*. A `Refusal::Tls` is
    /// deliberately not in the skip list — that is the failure this exists to
    /// catch.
    #[test]
    fn a_real_https_host_can_actually_be_fetched() {
        let policy = Policy::new(["example.com"]);
        match fetch(
            &policy,
            "t",
            "https://example.com/",
            Duration::from_secs(10),
        ) {
            Ok(response) => {
                let text = String::from_utf8_lossy(&response);
                assert!(
                    text.starts_with("HTTP/1.1 "),
                    "expected an HTTP response, got: {}",
                    &text[..text.len().min(80)]
                );
            }
            Err(Refusal::Io | Refusal::Unresolvable | Refusal::Timeout) => {
                eprintln!("SKIPPED: no outbound network from this machine");
            }
            Err(other) => {
                panic!("https fetch failed for a reason that is not the network: {other}")
            }
        }
    }

    #[test]
    fn a_root_store_is_actually_loaded() {
        // An empty root store would fail every handshake, and the failure would
        // look exactly like a misconfigured remote. Cheap to assert, expensive
        // to diagnose.
        assert!(tls_config().is_ok());
        assert!(
            !webpki_roots::TLS_SERVER_ROOTS.is_empty(),
            "no trust anchors: every https fetch would fail as untrusted"
        );
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
        assert!(!policy.allows("t", "169.254.169.254"));
        assert_eq!(
            fetch(
                &policy,
                "t",
                "http://169.254.169.254/",
                Duration::from_secs(1)
            ),
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
            fetch(&policy, "t", "http://localhost:1/", Duration::from_secs(1)),
            Err(Refusal::PrivateAddress)
        );
    }

    #[test]
    fn an_exhausted_budget_refuses_before_opening_a_socket() {
        // §6.1's epoch deadline cannot interrupt a guest parked in a host call,
        // so the budget has to be checked here or it stops being a bound.
        let policy = Policy::new(["example.com"]);
        assert_eq!(
            fetch(&policy, "t", "http://example.com/", Duration::ZERO),
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
                "t",
                "http://this-should-never-be-resolved.invalid/",
                Duration::from_secs(5)
            ),
            Err(Refusal::HostNotAllowed)
        );
    }
}
