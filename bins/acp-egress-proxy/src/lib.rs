//! acp-egress-proxy — the allowlisting egress proxy for attempt pods in `egress.mode: proxy`.
//!
//! Guarantees (together with the `egress=proxy` NetworkPolicy, which lets agent pods reach
//! only DNS, the ingest API and this proxy):
//!
//! * **CONNECT only.** Plain-HTTP proxy requests (`GET http://...`) are refused, so every
//!   tunnel is end-to-end TLS chosen by the client; the proxy never sees plaintext and never
//!   terminates TLS.
//! * **Hostname allowlist.** `api.anthropic.com` matches exactly; `.openai.com` matches
//!   `openai.com` and every subdomain. IP-literal targets are refused (an allowlist of names
//!   is meaningless if the client can name an address).
//! * **Port allowlist** (default 443).
//! * **No private destinations.** After resolution, every address must be public (no
//!   loopback, RFC 1918, CGNAT, link-local incl. the metadata endpoint, ULA, multicast,
//!   unspecified, site-local, discard, Teredo, 6to4-relay-anycast, nor IPv6 ranges
//!   embedding a non-public IPv4 address — NAT64 `64:ff9b::/96` + `64:ff9b:1::/48`,
//!   6to4 `2002::/16`); a name that resolves to any non-public address is refused,
//!   so DNS cannot be used to reach cluster-internal services through the proxy.
//! * Bounded request heads (8 KiB, 10 s), connect timeout, maximum tunnel lifetime and a
//!   connection limit. One JSON log line per decision (host, port, decision, reason, bytes) —
//!   never payload.
//!
//! What it does NOT do: it cannot tell a legitimate request to an allowlisted provider from
//! an agent sending data to the same provider, and it does not see DNS queries (NetworkPolicy
//! allows cluster DNS; see README "Network model").

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub const MAX_HEAD_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    exact: HashSet<String>,
    suffixes: Vec<String>,
}

fn valid_pattern(p: &str) -> bool {
    let body = p.strip_prefix('.').unwrap_or(p);
    !body.is_empty()
        && body.len() <= 253
        && body
            .split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && body.parse::<IpAddr>().is_err()
}

impl Allowlist {
    /// Patterns: `host.example.com` (exact) or `.example.com` (domain + subdomains).
    pub fn parse<I, S>(patterns: I) -> Result<Allowlist, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut a = Allowlist::default();
        for p in patterns {
            let p = p.as_ref().trim().trim_end_matches('.').to_ascii_lowercase();
            if p.is_empty() {
                continue;
            }
            if !valid_pattern(&p) {
                return Err(format!("invalid allowlist entry {p:?} (hostnames or .domain suffixes only)"));
            }
            match p.strip_prefix('.') {
                Some(domain) => a.suffixes.push(domain.to_string()),
                None => {
                    a.exact.insert(p);
                }
            }
        }
        Ok(a)
    }

    /// One pattern per line; `#` starts a comment.
    pub fn parse_file_contents(text: &str) -> Result<Allowlist, String> {
        Allowlist::parse(text.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()))
    }

    pub fn allows(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if self.exact.contains(&h) {
            return true;
        }
        self.suffixes.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// IPv4 address embedded in the low 32 bits of two IPv6 segments.
fn embedded_v4(hi: u16, lo: u16) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new((hi >> 8) as u8, (hi & 0xff) as u8, (lo >> 8) as u8, (lo & 0xff) as u8))
}

/// Publicly routable unicast address?
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay anycast (V7)
                || (o[0] == 198 && (18..=19).contains(&o[1])) // benchmarking
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            // IPv6 ranges embedding an IPv4 address (V7): the embedded address
            // must itself be public, otherwise the range is a tunnel into
            // non-public space.
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
                return is_public(embedded_v4(s[6], s[7])); // NAT64 64:ff9b::/96
            }
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
                return is_public(embedded_v4(s[6], s[7])); // NAT64 local-use 64:ff9b:1::/48
            }
            if s[0] == 0x2002 {
                return is_public(embedded_v4(s[1], s[2])); // 6to4 2002::/16
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xffc0) == 0xfec0 // site-local (V7)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] == 0x0000) // Teredo 2001::/32 (V7)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)) // discard 100::/64 (V7)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub allow: Allowlist,
    pub ports: Vec<u16>,
    /// Tests only: permit loopback/private destinations.
    pub allow_private: bool,
    pub header_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_tunnel: Duration,
    pub max_connections: usize,
}

impl ProxyConfig {
    pub fn new(allow: Allowlist) -> ProxyConfig {
        ProxyConfig {
            allow,
            ports: vec![443],
            allow_private: false,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            max_tunnel: Duration::from_secs(6 * 3600),
            max_connections: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { host: String, port: u16, addrs: Vec<SocketAddr> },
    Deny { status: u16, reason: String },
}

fn deny(status: u16, reason: impl Into<String>) -> Decision {
    Decision::Deny { status, reason: reason.into() }
}

/// Split `host:port` / `[v6]:port`.
fn split_target(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((h.to_string(), p.parse().ok()?));
    }
    let (h, p) = target.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// Parse the request head and decide (resolving the host when needed).
pub async fn decide(cfg: &ProxyConfig, head: &str) -> (Decision, String, String) {
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    if method != "CONNECT" {
        return (deny(403, "only CONNECT tunnels are allowed"), method, target);
    }
    let Some((host, port)) = split_target(&target) else {
        return (deny(400, "malformed CONNECT target"), method, target);
    };
    if host.parse::<IpAddr>().is_ok() {
        return (deny(403, "IP-literal destinations are not allowed"), method, target);
    }
    if !cfg.ports.contains(&port) {
        return (deny(403, format!("port {port} is not allowed")), method, target);
    }
    if !cfg.allow.allows(&host) {
        return (deny(403, "host is not on the allowlist"), method, target);
    }
    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout(cfg.connect_timeout, tokio::net::lookup_host((host.as_str(), port))).await {
            Ok(Ok(a)) => a.collect(),
            _ => return (deny(502, "name resolution failed"), method, target),
        };
    if addrs.is_empty() {
        return (deny(502, "name resolution returned no addresses"), method, target);
    }
    if !cfg.allow_private && !resolution_is_public(&addrs) {
        return (deny(403, "host resolves to a non-public address"), method, target);
    }
    (Decision::Allow { host, port, addrs }, method, target)
}

/// Every resolved address must be public (V7). Tested directly with synthetic
/// addresses — `decide` itself resolves via the system DNS, which tests cannot
/// steer at will (the `localhost` case below covers `decide` end to end).
fn resolution_is_public(addrs: &[SocketAddr]) -> bool {
    addrs.iter().all(|a| is_public(a.ip()))
}

/// Try every resolved address in turn, each with its own timeout; return the
/// first success and the address used (V7 fallback).
async fn connect_any(addrs: &[SocketAddr], timeout: Duration) -> Option<(TcpStream, SocketAddr)> {
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Some((s, *addr)),
            _ => continue,
        }
    }
    None
}

/// Copy one direction, adding every successfully written chunk to `counter`
/// immediately (V7): `tokio::io::copy` only reports its count at EOF, so a
/// `max_tunnel` timeout would drop the future before the assignment and lose
/// the partial count. EOF or either error ends the direction (with shutdown,
/// mirroring `copy_bidirectional` half-close semantics).
async fn copy_counted_dir<R, W>(mut reader: R, mut writer: W, counter: &std::sync::atomic::AtomicU64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
}

/// Relay both directions with byte counters that survive `max_tunnel` expiry
/// (V7): unlike `copy_bidirectional`, a timeout still reports partial bytes.
/// Runs both directions in one task (no `Send` bound needed); the timeout
/// drops the halves, closing both connections.
async fn copy_counted<C, U>(client: C, upstream: U, max_tunnel: Duration) -> (u64, u64)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    use std::sync::atomic::{AtomicU64, Ordering};
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let c2s = copy_counted_dir(cr, uw, &up);
    let s2c = copy_counted_dir(ur, cw, &down);
    let _ = tokio::time::timeout(max_tunnel, async {
        tokio::join!(c2s, s2c);
    })
    .await;
    (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed))
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf[pos + 4..].to_vec();
            buf.truncate(pos);
            return Ok((String::from_utf8_lossy(&buf).to_string(), rest));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request head too large"));
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "client closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

struct LogEntry<'a> {
    peer: &'a str,
    method: &'a str,
    target: &'a str,
    decision: &'a str,
    reason: &'a str,
    up: u64,
    down: u64,
    started: Instant,
}

fn log(e: LogEntry<'_>) {
    let line = serde_json::json!({
        "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "client": e.peer, "method": e.method, "target": e.target, "decision": e.decision, "reason": e.reason,
        "bytesUp": e.up, "bytesDown": e.down, "ms": e.started.elapsed().as_millis() as u64,
    });
    tracing::info!(target: "acp_egress", "{line}");
}

/// Serve one client connection.
pub async fn handle<S>(mut client: S, peer: String, cfg: Arc<ProxyConfig>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let (head, leftover) = match tokio::time::timeout(cfg.header_timeout, read_head(&mut client)).await {
        Ok(Ok(h)) => h,
        _ => {
            let _ =
                client.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await;
            log(LogEntry {
                peer: &peer,
                method: "",
                target: "",
                decision: "deny",
                reason: "bad or slow request head",
                up: 0,
                down: 0,
                started,
            });
            return;
        }
    };
    let (decision, method, target) = decide(&cfg, &head).await;
    let (host, port, addrs) = match decision {
        Decision::Deny { status, reason } => {
            let text = match status {
                400 => "Bad Request",
                502 => "Bad Gateway",
                _ => "Forbidden",
            };
            let body = format!("acp-egress-proxy: {reason}\n");
            let _ = client
                .write_all(
                    format!("HTTP/1.1 {status} {text}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                        .as_bytes(),
                )
                .await;
            log(LogEntry {
                peer: &peer,
                method: &method,
                target: &target,
                decision: "deny",
                reason: &reason,
                up: 0,
                down: 0,
                started,
            });
            return;
        }
        Decision::Allow { host, port, addrs } => (host, port, addrs),
    };
    // A name may resolve to both ::1 and 127.0.0.1 while only one accepts
    // connections; using only addrs[0] made localhost tests flaky.
    let Some((upstream, connected_addr)) = connect_any(&addrs, cfg.connect_timeout).await else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await;
        log(LogEntry {
            peer: &peer,
            method: &method,
            target: &target,
            decision: "deny",
            reason: "upstream connect failed",
            up: 0,
            down: 0,
            started,
        });
        return;
    };
    let _ = upstream.set_nodelay(true);
    let mut upstream = upstream;
    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
        return;
    }
    let mut up = 0u64;
    if !leftover.is_empty() {
        if upstream.write_all(&leftover).await.is_err() {
            return;
        }
        up += leftover.len() as u64;
    }
    // Byte counters survive max_tunnel expiry (V7).
    let (u, d) = copy_counted(client, upstream, cfg.max_tunnel).await;
    let via = connected_addr.to_string();
    log(LogEntry {
        peer: &peer,
        method: &method,
        target: &format!("{host}:{port}"),
        decision: "allow",
        reason: &via,
        up: up + u,
        down: d,
        started,
    });
}

/// Serve TCP clients until the listener fails.
pub async fn serve_tcp(listener: TcpListener, cfg: Arc<ProxyConfig>) {
    let slots = Arc::new(Semaphore::new(cfg.max_connections));
    while let Ok((s, peer)) = listener.accept().await {
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(s);
            continue;
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle(s, peer.to_string(), cfg).await;
            drop(permit);
        });
    }
}

/// Serve clients on a Unix socket (used by the local isolation harness).
pub async fn serve_unix(listener: UnixListener, cfg: Arc<ProxyConfig>) {
    let slots = Arc::new(Semaphore::new(cfg.max_connections));
    while let Ok((s, _)) = listener.accept().await {
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(s);
            continue;
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle(s, "unix".into(), cfg).await;
            drop(permit);
        });
    }
}

/// TCP -> Unix socket relay: inside an isolated network namespace this is the only route
/// to the proxy (it stands in for the pod network path to the proxy Service).
pub async fn relay(listener: TcpListener, unix: &Path) {
    let unix = unix.to_path_buf();
    while let Ok((mut s, _)) = listener.accept().await {
        let unix = unix.clone();
        tokio::spawn(async move {
            if let Ok(mut u) = UnixStream::connect(&unix).await {
                let _ = tokio::io::copy_bidirectional(&mut s, &mut u).await;
            }
        });
    }
}

/// Bring the loopback interface of the current network namespace up.
pub fn loopback_up() -> std::io::Result<()> {
    use nix::libc;
    // SAFETY: plain ioctl(2) calls on a private socket with a zero-initialized ifreq.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo\0".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        let r = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr);
        if r < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        let r = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr);
        let e = std::io::Error::last_os_error();
        libc::close(fd);
        if r < 0 {
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_semantics() {
        let a = Allowlist::parse(["api.anthropic.com", ".openai.com", "github.com"]).unwrap();
        assert!(a.allows("api.anthropic.com"));
        assert!(a.allows("API.Anthropic.com."));
        assert!(!a.allows("evil-api.anthropic.com"));
        assert!(!a.allows("anthropic.com"));
        assert!(a.allows("openai.com"));
        assert!(a.allows("chatgpt.api.openai.com"));
        assert!(!a.allows("openai.com.evil.net"));
        assert!(!a.allows("notopenai.com"));
        assert!(!a.allows("gist.github.com"));
        assert!(Allowlist::parse(["*.example.com"]).is_err());
        assert!(Allowlist::parse(["10.0.0.1"]).is_err());
        let f = Allowlist::parse_file_contents("# providers\n.chatgpt.com   # codex\n\napi.anthropic.com\n").unwrap();
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn private_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "224.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "2606:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn special_v4_and_v6_ranges_are_classified() {
        // V7 table tests: each range from the plan, denied and (where the
        // range embeds an IPv4) allowed-with-public-embedded cases.
        for ip in [
            "192.88.99.1",   // 6to4 relay anycast
            "192.88.99.254", // 6to4 relay anycast
            "64:ff9b::a00:1", // NAT64 of 10.0.0.1
            "64:ff9b::c000:201", // NAT64 of documentation 192.0.2.1
            "64:ff9b:1::a00:1", // NAT64 local-use of 10.0.0.1
            "2002:a00:1::1", // 6to4 of 10.0.1.0
            "2001::1",       // Teredo
            "2001:0:abcd::1", // Teredo
            "fec0::1",       // site-local
            "100::1",        // discard
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "192.88.100.1",    // adjacent to the relay range: public
            "64:ff9b::0101:0101", // NAT64 of public 1.1.1.1: still public
            "64:ff9b:1::0808:0808", // NAT64 local-use of public 8.8.8.8
            "2002:0101:0101::1", // 6to4 of public 1.1.1.1
            "2001:4860:4860::8888", // public 2001:4860::/32, not Teredo
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn resolution_with_embedded_non_public_v4_is_refused() {
        // V7: `decide` resolves via the system DNS, which tests cannot steer
        // at will — so the post-resolution predicate is tested directly with
        // synthetic addresses (the `localhost` case in `decisions` covers
        // `decide` end to end).
        let sock = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 443);
        assert!(!resolution_is_public(&[sock("64:ff9b::a00:1")]));
        assert!(!resolution_is_public(&[sock("1.1.1.1"), sock("64:ff9b::a00:1")]));
        assert!(resolution_is_public(&[sock("1.1.1.1"), sock("2606:4700:4700::1111")]));
        assert!(resolution_is_public(&[sock("64:ff9b::0101:0101")]));
    }

    #[tokio::test]
    async fn connect_falls_back_to_the_next_address() {
        // V7: the first resolved address refuses, the second answers — the
        // tunnel must still establish, via the working address.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = live.accept().await {
                tokio::spawn(async move {
                    let _ = s.write_all(b"up").await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });
        let (mut stream, via) =
            connect_any(&[dead_addr, live_addr], Duration::from_secs(5)).await.expect("fallback connects");
        assert_eq!(via, live_addr);
        let mut b = [0u8; 2];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"up");
        // all dead: no tunnel.
        assert!(connect_any(&[dead_addr], Duration::from_secs(2)).await.is_none());
    }

    #[tokio::test]
    async fn byte_counters_survive_tunnel_timeout() {
        // V7: partial bytes are reported even when max_tunnel expires.
        let (cc, mut cu) = tokio::io::duplex(4096);
        let (uc, mut uu) = tokio::io::duplex(4096);
        let relay = tokio::spawn(copy_counted(cc, uc, Duration::from_millis(80)));
        cu.write_all(&[1u8; 100]).await.unwrap();
        uu.write_all(&[2u8; 50]).await.unwrap();
        // Nothing reads: both directions stall with full buffers pending, the
        // timeout fires, and the counters must still show the moved bytes.
        let (up, down) = relay.await.unwrap();
        assert_eq!((up, down), (100, 50));
        // ...and the bytes really moved.
        let mut buf = [0u8; 100];
        uu.read_exact(&mut buf).await.unwrap();
        assert!(buf.iter().all(|b| *b == 1));
        let mut buf = [0u8; 50];
        cu.read_exact(&mut buf).await.unwrap();
        assert!(buf.iter().all(|b| *b == 2));
    }

    #[tokio::test]
    async fn decisions() {
        let cfg = ProxyConfig::new(Allowlist::parse(["localhost", "api.anthropic.com"]).unwrap());
        let d = |h: &'static str| {
            let cfg = cfg.clone();
            async move { decide(&cfg, h).await.0 }
        };
        assert!(matches!(d("GET http://example.com/ HTTP/1.1").await, Decision::Deny { status: 403, .. }));
        assert!(matches!(d("CONNECT 1.2.3.4:443 HTTP/1.1").await, Decision::Deny { status: 403, .. }));
        assert!(matches!(d("CONNECT [::1]:443 HTTP/1.1").await, Decision::Deny { status: 403, .. }));
        assert!(matches!(d("CONNECT api.anthropic.com:22 HTTP/1.1").await, Decision::Deny { status: 403, .. }));
        assert!(matches!(d("CONNECT evil.example:443 HTTP/1.1").await, Decision::Deny { status: 403, .. }));
        // allowlisted, but resolves to loopback
        match d("CONNECT localhost:443 HTTP/1.1").await {
            Decision::Deny { status: 403, reason } => assert!(reason.contains("non-public"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(d("CONNECT nonsense HTTP/1.1").await, Decision::Deny { status: 400, .. }));
    }

    async fn roundtrip(proxy: SocketAddr, request: String) -> (String, Vec<u8>) {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = vec![];
        let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
        let text = String::from_utf8_lossy(&out).to_string();
        (text.lines().next().unwrap_or("").to_string(), out)
    }

    #[tokio::test]
    async fn tunnels_to_allowed_hosts_and_refuses_the_rest() {
        // upstream "provider" echoing a greeting
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                let mut b = [0u8; 5];
                let _ = s.read_exact(&mut b).await;
                let _ = s.write_all(b"hello from provider").await;
            }
        });
        let mut cfg = ProxyConfig::new(Allowlist::parse(["localhost"]).unwrap());
        cfg.ports = vec![up_port];
        cfg.allow_private = true;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = l.local_addr().unwrap();
        tokio::spawn(serve_tcp(l, Arc::new(cfg)));
        let (status, body) =
            roundtrip(proxy, format!("CONNECT localhost:{up_port} HTTP/1.1\r\nHost: localhost\r\n\r\nping!")).await;
        assert!(status.contains("200"), "{status}");
        assert!(String::from_utf8_lossy(&body).contains("hello from provider"));
        let (status, _) = roundtrip(proxy, format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n")).await;
        assert!(status.contains("403"), "{status}");
        let (status, _) = roundtrip(proxy, "GET http://localhost/ HTTP/1.1\r\n\r\n".into()).await;
        assert!(status.contains("403"), "{status}");
    }
}
