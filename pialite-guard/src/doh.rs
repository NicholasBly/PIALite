//! DNS-over-HTTPS client: sends a DNS query to NextDNS over TLS and returns
//! the answer. Keeps a few connections open so most lookups skip the TLS
//! handshake. Connects to fixed IPs (no DNS needed to find the DNS server).
//!
//! Fallback (review N-15): if a server fails at ANY step - TCP, TLS handshake,
//! certificate, HTTP, or a bad answer - the next bootstrap address is tried,
//! all within one deadline per lookup. Every address gets the same host name
//! (SNI) and the same full certificate check; there is never a fallback to
//! plain DNS or to an unverified connection. A certificate failure is logged
//! on its own (it can mean someone is intercepting the connection). The
//! address that last worked is tried first next time.
//!
//! The deadline is real (review V3-07): every single socket read and write -
//! TCP connect, TLS handshake, request, headers, body - is limited to what is
//! left of it, so a server that answers one byte at a time can't stretch a
//! lookup. Each address gets a fair share of what's left, so one slow server
//! can't use up the time of the next.

use crate::{dns, http};
use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Conn = rustls::StreamOwned<rustls::ClientConnection, Sock>;

/// A TCP socket whose every read and write gets at most what is left until
/// `until` (and never more than `io`) - see the module notes.
pub struct Sock {
    tcp: TcpStream,
    io: Duration,
    until: Option<Instant>,
}

impl Sock {
    fn new(tcp: TcpStream, io: Duration) -> Sock {
        let _ = tcp.set_nodelay(true);
        Sock { tcp, io, until: None }
    }
    /// Set the deadline for the next exchange on this socket.
    fn arm(&mut self, until: Instant) {
        self.until = Some(until);
    }
    fn budget(&self) -> std::io::Result<Duration> {
        let left = match self.until {
            Some(u) => u
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "lookup deadline reached"))?,
            None => self.io,
        };
        Ok(left.min(self.io))
    }
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let t = self.budget()?;
        self.tcp.set_read_timeout(Some(t))?;
        self.tcp.read(buf)
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let t = self.budget()?;
        self.tcp.set_write_timeout(Some(t))?;
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

const POOL_MAX: usize = 4;
const IDLE_MAX: Duration = Duration::from_secs(30);
/// A kept-alive connection gets this long to answer before we give up on it
/// and use a fresh one (it may have died with a VPN reconnect).
const REUSED_TIMEOUT: Duration = Duration::from_secs(2);
/// Opening a connection ahead of time (after the VPN connects).
const WARM_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// One lookup, all servers included, never takes longer than this.
const DEADLINE: Duration = Duration::from_secs(8);
/// A bad certificate is logged at most this often.
const CERT_LOG_EVERY: Duration = Duration::from_secs(600);

pub trait Resolve: Send + Sync {
    fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, String>;
    /// Forget open connections (the network changed: VPN reconnect, wake-up).
    fn reset(&self) {}
    /// Open a connection ahead of the first lookup (the VPN just connected),
    /// so that lookup doesn't wait for a TCP + TLS handshake.
    fn warm(&self) {}
}

pub struct Doh {
    tls: Arc<rustls::ClientConfig>,
    host: String,
    server_name: ServerName<'static>,
    path: String,
    addrs: Vec<SocketAddr>,
    next_addr: AtomicUsize,
    pool: Mutex<Vec<(Instant, Conn)>>,
    io_timeout: Duration,
    deadline: Duration,
    cert_logged: Mutex<Option<Instant>>,
    /// +1 at every reset (network change): a connection opened ahead of
    /// time is only kept if no reset happened meanwhile (review V60-09).
    epoch: AtomicU64,
    /// A warm-up is running (one at a time).
    warming: AtomicBool,
    /// DNS over TLS (RFC 7858: 2-byte length + message on a TLS stream to
    /// port 853) instead of HTTPS - for providers without HTTP/1.1 DoH.
    dot: bool,
}

/// Why one server didn't work.
enum Fail {
    /// The certificate didn't check out - refused, logged on its own.
    Cert(String),
    Other(String),
}
impl Fail {
    fn text(&self) -> &str {
        match self {
            Fail::Cert(e) | Fail::Other(e) => e,
        }
    }
}

/// Was this I/O error a TLS certificate rejection?
fn cert_error(e: &std::io::Error) -> bool {
    e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()).is_some_and(|r| {
        matches!(r, rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented | rustls::Error::UnsupportedNameType)
    })
}

pub fn tls_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    tls_config_alpn(roots, &[b"http/1.1"])
}

fn tls_config_alpn(roots: rustls::RootCertStore, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

pub fn public_roots() -> rustls::RootCertStore {
    rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

/// One HTTPS GET to a given IP with a given host name (NextDNS self-test),
/// 15 s at most in total.
pub fn https_get(addr: SocketAddr, host: &str, path: &str) -> Result<http::Reply, String> {
    // the clock starts before connecting (review V4-11)
    let until = Instant::now() + Duration::from_secs(15);
    let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| format!("connect {addr}: {e}"))?;
    let mut sock = Sock::new(tcp, IO_TIMEOUT);
    sock.arm(until);
    let name = ServerName::try_from(host.to_string()).map_err(|_| format!("bad host name {host}"))?;
    let conn = rustls::ClientConnection::new(tls_config(public_roots()), name).map_err(|e| format!("TLS setup: {e}"))?;
    let mut s = rustls::StreamOwned::new(conn, sock);
    http::get(&mut s, host, path)
}

/// HTTPS GET by host name (resolved by the system), for update checks and
/// downloads: bodies up to `max_body`, 120 s at most in total.
pub fn https_get_url(host: &str, path: &str, max_body: usize) -> Result<http::Reply, String> {
    use std::net::ToSocketAddrs;
    let until = Instant::now() + Duration::from_secs(120);
    let addrs: Vec<SocketAddr> = (host, 443).to_socket_addrs().map_err(|e| format!("looking up {host}: {e}"))?.collect();
    let mut last = format!("no address for {host}");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(tcp) => {
                let mut sock = Sock::new(tcp, Duration::from_secs(30));
                sock.arm(until);
                let name = ServerName::try_from(host.to_string()).map_err(|_| format!("bad host name {host}"))?;
                let conn = rustls::ClientConnection::new(tls_config(public_roots()), name).map_err(|e| format!("TLS setup: {e}"))?;
                let mut s = rustls::StreamOwned::new(conn, sock);
                return http::get_max(&mut s, host, path, max_body);
            }
            Err(e) => last = format!("connect {addr}: {e}"),
        }
    }
    Err(last)
}

impl Doh {
    pub fn new(tls: Arc<rustls::ClientConfig>, host: &str, path: &str, addrs: Vec<SocketAddr>) -> Result<Self, String> {
        if addrs.is_empty() {
            return Err("no DoH server addresses".into());
        }
        let server_name = ServerName::try_from(host.to_string()).map_err(|_| format!("bad DoH host name {host}"))?;
        Ok(Doh {
            tls,
            host: host.into(),
            server_name,
            path: path.into(),
            addrs,
            next_addr: AtomicUsize::new(0),
            pool: Mutex::new(Vec::new()),
            io_timeout: IO_TIMEOUT,
            deadline: DEADLINE,
            cert_logged: Mutex::new(None),
            epoch: AtomicU64::new(0),
            warming: AtomicBool::new(false),
            dot: false,
        })
    }

    /// Speak DNS over TLS on these addresses instead of HTTPS.
    pub fn with_dot(mut self, on: bool) -> Self {
        self.dot = on;
        self
    }

    /// Keep a connection opened ahead of time - only if it belongs to the
    /// current network (no reset since `epoch` was read).
    fn keep_warm(&self, epoch: u64, conn: Conn) -> bool {
        let mut pool = self.pool.lock().unwrap(); // reset() clears under this lock too
        if self.epoch.load(Ordering::SeqCst) != epoch || !pool.is_empty() {
            return false;
        }
        pool.push((Instant::now(), conn));
        true
    }

    #[cfg(test)]
    fn with_timeouts(mut self, io: Duration, deadline: Duration) -> Self {
        self.io_timeout = io;
        self.deadline = deadline;
        self
    }

    /// From the config's bootstrap IP list (port 443, or 853 for DNS over TLS).
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self, String> {
        let dot = cfg.dot();
        let port = cfg.port();
        let addrs =
            cfg.doh_bootstrap.iter().filter_map(|ip| ip.parse::<std::net::IpAddr>().ok()).map(|ip| SocketAddr::new(ip, port)).collect();
        // a custom server with its own certificate authority trusts ONLY that
        let roots =
            if cfg.provider() == "custom" && cfg.doh_custom_ca { custom_roots(&crate::config::custom_ca_path())? } else { public_roots() };
        let tls = if dot { tls_config_alpn(roots, &[b"dot"]) } else { tls_config(roots) };
        Ok(Doh::new(tls, &cfg.doh_host, &cfg.doh_path(), addrs)?.with_dot(dot))
    }

    /// A new, fully verified TLS connection to one address, all of it before
    /// `until` (handshake done here, so certificate problems are told apart
    /// from the rest).
    fn connect(&self, addr: SocketAddr, until: Instant) -> Result<Conn, Fail> {
        let left =
            until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(Fail::Other(format!("{addr}: out of time")))?;
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT.min(left)).map_err(|e| Fail::Other(format!("connect {addr}: {e}")))?;
        let mut sock = Sock::new(tcp, self.io_timeout);
        sock.arm(until);
        let conn = rustls::ClientConnection::new(self.tls.clone(), self.server_name.clone())
            .map_err(|e| Fail::Other(format!("TLS setup: {e}")))?;
        let mut s = rustls::StreamOwned::new(conn, sock);
        while s.conn.is_handshaking() {
            if let Err(e) = s.conn.complete_io(&mut s.sock) {
                return Err(if cert_error(&e) {
                    Fail::Cert(format!("{addr}: certificate for {} NOT valid ({e}) - refused", self.host))
                } else {
                    Fail::Other(format!("{addr}: TLS handshake failed ({e})"))
                });
            }
        }
        Ok(s)
    }

    fn pooled(&self) -> Option<Conn> {
        let mut pool = self.pool.lock().unwrap();
        while let Some((since, conn)) = pool.pop() {
            if since.elapsed() < IDLE_MAX {
                return Some(conn);
            }
        }
        None
    }

    fn give_back(&self, conn: Conn) {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < POOL_MAX {
            pool.push((Instant::now(), conn));
        }
    }

    /// Send the query and accept only a real DNS answer to it.
    fn exchange(&self, conn: &mut Conn, query: &[u8]) -> Result<http::Reply, String> {
        let reply = if self.dot { dot_exchange(conn, query)? } else { http::post_dns(conn, &self.host, &self.path, query)? };
        validate(&reply, query)?;
        Ok(reply)
    }
}

/// The certificate authorities in a PEM file (a home server's own CA).
pub fn custom_roots(path: &std::path::Path) -> Result<rustls::RootCertStore, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let pem = std::fs::read(path).map_err(|e| format!("the DNS server's certificate file {}: {e}", path.display()))?;
    crate::config::check_ca_pem(&pem)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
    Ok(roots)
}

/// One DNS-over-TLS round trip: 2-byte length + query, 2-byte length + answer.
fn dot_exchange(conn: &mut Conn, query: &[u8]) -> Result<http::Reply, String> {
    use std::io::{Read, Write};
    let len = u16::try_from(query.len()).map_err(|_| "query too long")?;
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query);
    conn.write_all(&msg).and_then(|_| conn.flush()).map_err(|e| format!("send: {e}"))?;
    let mut n = [0u8; 2];
    conn.read_exact(&mut n).map_err(|e| format!("no answer: {e}"))?;
    let n = u16::from_be_bytes(n) as usize;
    if n < 12 {
        return Err("DoT answer too short".into());
    }
    let mut body = vec![0u8; n];
    conn.read_exact(&mut body).map_err(|e| format!("answer cut off: {e}"))?;
    // same checks as DoH answers (validate), so pretend the HTTP parts
    Ok(http::Reply { status: 200, location: String::new(), body, content_type: "application/dns-message".into(), keep_alive: true })
}

/// RFC 8484 answer checks (audit P2-14): right content type, ID 0 as sent,
/// marked as a response, and answering the same question.
fn validate(reply: &http::Reply, query: &[u8]) -> Result<(), String> {
    if !reply.content_type.starts_with("application/dns-message") {
        return Err(format!("the DNS provider sent '{}' instead of a DNS answer", reply.content_type));
    }
    if dns::id(&reply.body) != Some(0) {
        return Err("DoH answer has the wrong ID".into());
    }
    dns::check_response(&reply.body, query).map_err(|e| format!("bad DoH answer: {e}"))
}

impl Doh {
    fn log_cert(&self, e: &str) {
        let mut last = self.cert_logged.lock().unwrap();
        if last.is_none_or(|t| t.elapsed() >= CERT_LOG_EVERY) {
            *last = Some(Instant::now());
            crate::config::log(&format!("WARNING: DNS server {e} - possible interception, trying the other address"));
        }
    }

    /// The query on one connection; kept for reuse if the server allows.
    fn on(&self, mut conn: Conn, q: &[u8]) -> Result<Vec<u8>, String> {
        let reply = self.exchange(&mut conn, q)?;
        if reply.keep_alive {
            self.give_back(conn);
        }
        Ok(reply.body)
    }
}

impl Resolve for Doh {
    fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        let orig_id = dns::id(query).ok_or("short query")?;
        // RFC 8484: use ID 0 so answers are cache friendly; put it back after.
        let mut q = query.to_vec();
        dns::set_id(&mut q, 0);
        let deadline = Instant::now() + self.deadline;

        // 1. a kept-alive connection, with a short time limit: it may have
        //    died with a VPN reconnect
        if let Some(mut c) = self.pooled() {
            c.sock.arm((Instant::now() + REUSED_TIMEOUT).min(deadline));
            if let Ok(mut body) = self.on(c, &q) {
                dns::set_id(&mut body, orig_id);
                return Ok(body);
            }
        }
        // 2. a fresh connection to each server in turn, the last good one first
        let n = self.addrs.len();
        let start = self.next_addr.load(Ordering::Relaxed);
        let mut errors = Vec::new();
        for i in 0..n {
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
                errors.push("out of time".to_string());
                break;
            };
            let idx = (start + i) % n;
            let addr = self.addrs[idx];
            // a fair share of what's left for this address (all of it for the last one)
            let until = Instant::now() + left / (n - i) as u32;
            let r = self.connect(addr, until).and_then(|c| self.on(c, &q).map_err(|e| Fail::Other(format!("{addr}: {e}"))));
            match r {
                Ok(mut body) => {
                    self.next_addr.store(idx, Ordering::Relaxed);
                    dns::set_id(&mut body, orig_id);
                    return Ok(body);
                }
                Err(f) => {
                    if let Fail::Cert(e) = &f {
                        self.log_cert(e);
                    }
                    errors.push(f.text().to_string());
                }
            }
        }
        // next time, start with the other server
        self.next_addr.store((start + 1) % n, Ordering::Relaxed);
        Err(errors.join("; "))
    }

    fn reset(&self) {
        let mut pool = self.pool.lock().unwrap();
        self.epoch.fetch_add(1, Ordering::SeqCst);
        pool.clear();
    }

    fn warm(&self) {
        if self.addrs.is_empty() || !self.pool.lock().unwrap().is_empty() || self.warming.swap(true, Ordering::SeqCst) {
            return;
        }
        let epoch = self.epoch.load(Ordering::SeqCst);
        let addr = self.addrs[self.next_addr.load(Ordering::Relaxed) % self.addrs.len()];
        if let Ok(c) = self.connect(addr, Instant::now() + WARM_TIMEOUT) {
            // a reconnect while this was opening: it belongs to the old network - drop it
            self.keep_warm(epoch, c);
        }
        self.warming.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicU32;

    /// Local fake NextDNS: real TLS with a self-signed cert for dns.nextdns.io.
    /// Answers each POST with the query echoed back (QR bit set). Returns
    /// (address, client TLS config trusting the cert, connections accepted).
    pub fn fake_server(close_after_each: bool) -> (SocketAddr, Arc<rustls::ClientConfig>, Arc<AtomicU32>) {
        fake_server_with(close_after_each, "")
    }

    /// `bad`: "" = correct answers, "ctype" = wrong content type,
    /// "question" = answers a different name, "id" = non-zero ID,
    /// "503" = HTTP error, "stall" = 2nd answer never comes, "drip" = one byte
    /// every 100 ms. All of these share ONE certificate (so a test of, say,
    /// HTTP 503 really reaches HTTP - not a certificate failure).
    pub fn fake_server_with(close_after_each: bool, bad: &'static str) -> (SocketAddr, Arc<rustls::ClientConfig>, Arc<AtomicU32>) {
        serve(close_after_each, bad, false)
    }

    /// A fake DNS-over-TLS server (shared certificate): echoes each query as
    /// an answer. `bad` = "id": a non-zero ID; "short": a 2-byte answer.
    pub fn fake_dot_server(bad: &'static str) -> SocketAddr {
        let (cert, key) = shared_cert().clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert)], rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()))
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let cfg = server_cfg.clone();
                std::thread::spawn(move || {
                    let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), tcp);
                    loop {
                        let mut n = [0u8; 2];
                        if s.read_exact(&mut n).is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(n) as usize];
                        if s.read_exact(&mut q).is_err() {
                            return;
                        }
                        q[2] |= 0x80;
                        if bad == "id" {
                            q[1] = 7;
                        }
                        let a = if bad == "short" { vec![1, 2] } else { q };
                        let mut out = (a.len() as u16).to_be_bytes().to_vec();
                        out.extend_from_slice(&a);
                        if s.write_all(&out).and_then(|_| s.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn dns_over_tls() {
        let (_, tls, _) = fake_server(false); // trusts the shared certificate
        let d = Doh::new(tls.clone(), "dns.nextdns.io", "/unused", vec![fake_dot_server("")]).unwrap().with_dot(true);
        let q = dns::build_query(0x1234, "example.com", 1).unwrap();
        for _ in 0..3 {
            // the second and third reuse the kept connection
            let a = d.resolve(&q).unwrap();
            assert_eq!(dns::id(&a), Some(0x1234), "the original ID is put back");
            assert!(dns::check_response(&a, &q).is_ok());
        }
        let bad = Doh::new(tls.clone(), "dns.nextdns.io", "/unused", vec![fake_dot_server("id")]).unwrap().with_dot(true);
        assert!(bad.resolve(&q).unwrap_err().contains("wrong ID"));
        let short = Doh::new(tls, "dns.nextdns.io", "/unused", vec![fake_dot_server("short")]).unwrap().with_dot(true);
        assert!(short.resolve(&q).unwrap_err().contains("too short"));
        // the real setting: Quad9 speaks DoT on port 853
        let mut c = crate::config::Config::default();
        c.set_provider("quad9", None).unwrap();
        let q9 = Doh::from_config(&c).unwrap();
        assert!(q9.dot && q9.addrs.iter().all(|a| a.port() == 853));
        c.set_provider("cloudflare", None).unwrap();
        let cf = Doh::from_config(&c).unwrap();
        assert!(!cf.dot && cf.addrs.iter().all(|a| a.port() == 443));
    }

    /// A home server with its own certificate authority: trusted through the
    /// CA file only (not the public roots), over DNS over TLS.
    #[test]
    fn home_server_with_its_own_ca() {
        let (cert, _) = shared_cert().clone();
        let b64 = |d: &[u8]| {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for c in d.chunks(3) {
                let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
                for i in 0..4 {
                    s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
                }
            }
            s
        };
        let dir = std::env::temp_dir().join(format!("pialite-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64(&cert));
        let f = dir.join("ca.pem");
        std::fs::write(&f, &pem).unwrap();
        assert_eq!(crate::config::check_ca_pem(pem.as_bytes()), Ok(1));
        assert!(crate::config::check_ca_pem(b"hello").is_err());
        let roots = custom_roots(&f).unwrap();
        let d = Doh::new(tls_config_alpn(roots, &[b"dot"]), "dns.nextdns.io", "", vec![fake_dot_server("")]).unwrap().with_dot(true);
        let q = dns::build_query(0x2222, "example.com", 1).unwrap();
        assert_eq!(dns::id(&d.resolve(&q).unwrap()), Some(0x2222), "answered through the home CA");
        // the public roots alone don't trust it
        let p =
            Doh::new(tls_config_alpn(public_roots(), &[b"dot"]), "dns.nextdns.io", "", vec![fake_dot_server("")]).unwrap().with_dot(true);
        assert!(p.resolve(&q).is_err());
        assert!(custom_roots(&dir.join("missing.pem")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A server with its OWN certificate, which the shared config doesn't trust.
    pub fn fake_server_own_cert() -> SocketAddr {
        serve(false, "", true).0
    }

    fn shared_cert() -> &'static (Vec<u8>, Vec<u8>) {
        static C: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        C.get_or_init(|| {
            let ck = rcgen::generate_simple_self_signed(vec!["dns.nextdns.io".to_string()]).unwrap();
            (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
        })
    }

    fn serve(close_after_each: bool, bad: &'static str, own_cert: bool) -> (SocketAddr, Arc<rustls::ClientConfig>, Arc<AtomicU32>) {
        let (cert, key) = if own_cert {
            let ck = rcgen::generate_simple_self_signed(vec!["dns.nextdns.io".to_string()]).unwrap();
            (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
        } else {
            shared_cert().clone()
        };
        let cert_der = rustls::pki_types::CertificateDer::from(cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_cfg = Arc::new(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicU32::new(0));
        let acc = accepted.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                acc.fetch_add(1, Ordering::SeqCst);
                let cfg = server_cfg.clone();
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(cfg).unwrap();
                    let mut s = rustls::StreamOwned::new(conn, tcp);
                    let mut served = 0;
                    loop {
                        let mut buf = Vec::new();
                        let mut tmp = [0u8; 2048];
                        // read headers
                        let hdr_end = loop {
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p;
                            }
                            match s.read(&mut tmp) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..hdr_end]).to_lowercase();
                        let len: usize =
                            head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                        let mut body = buf[hdr_end + 4..].to_vec();
                        while body.len() < len {
                            match s.read(&mut tmp) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => body.extend_from_slice(&tmp[..n]),
                            }
                        }
                        assert!(head.starts_with("post /abc123/test-pc http/1.1"), "{head}");
                        assert_eq!(&body[..2], &[0, 0], "query id must be 0 on the wire");
                        served += 1;
                        if bad == "stall" && served > 1 {
                            // like a connection that died with a VPN reconnect: never answers
                            std::thread::sleep(Duration::from_secs(20));
                            return;
                        }
                        body[2] |= 0x80;
                        match bad {
                            "question" => body[14] = b'z',
                            "id" => body[1] = 9,
                            _ => {}
                        }
                        let ctype = if bad == "ctype" { "text/html" } else { "application/dns-message" };
                        let conn_hdr = if close_after_each { "close" } else { "keep-alive" };
                        let status = if bad == "503" { "503 Service Unavailable" } else { "200 OK" };
                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\n\r\n",
                            body.len()
                        );
                        if bad == "drip" {
                            // answers, but one byte every 100 ms
                            for b in resp.as_bytes().iter().chain(body.iter()) {
                                if s.write_all(&[*b]).is_err() || s.flush().is_err() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(100));
                            }
                            continue;
                        }
                        let _ = s.write_all(resp.as_bytes());
                        let _ = s.write_all(&body);
                        let _ = s.flush();
                        if close_after_each {
                            s.conn.send_close_notify();
                            let _ = s.flush();
                            return;
                        }
                    }
                });
            }
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        (addr, tls_config(roots), accepted)
    }

    #[test]
    fn tls_roundtrip_and_reuse() {
        let (addr, tls, accepted) = fake_server(false);
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
        for id in [0x1234u16, 0x4321, 0x0042] {
            let q = dns::tests::query(id, None);
            let a = doh.resolve(&q).unwrap();
            assert_eq!(dns::id(&a), Some(id), "original id restored");
            assert_eq!(a[2] & 0x80, 0x80);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "one TLS connection reused");
        // after a network change the pool is dropped and a new connection is made
        doh.reset();
        assert!(doh.resolve(&dns::tests::query(5, None)).is_ok());
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "fresh connection after reset");
    }

    /// Review V60-09: a connection opened ahead of time is kept only for the
    /// network it was opened on; one warm-up at a time.
    #[test]
    fn warm_connection_belongs_to_its_network() {
        let (addr, tls, accepted) = fake_server(false);
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
        doh.warm();
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(doh.pool.lock().unwrap().len(), 1, "kept for the first lookup");
        assert!(doh.resolve(&dns::tests::query(7, None)).is_ok());
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "the lookup used the warm connection");
        // opened before a reset, finished after it: not kept
        doh.reset();
        let epoch = doh.epoch.load(Ordering::SeqCst);
        let c = doh.connect(addr, Instant::now() + Duration::from_secs(5)).ok().unwrap();
        doh.reset();
        assert!(!doh.keep_warm(epoch, c), "a connection from before the reset is dropped");
        assert!(doh.pool.lock().unwrap().is_empty());
        // while one warm-up runs, another doesn't start
        doh.warming.store(true, Ordering::SeqCst);
        doh.warm();
        assert!(doh.pool.lock().unwrap().is_empty());
        doh.warming.store(false, Ordering::SeqCst);
    }

    #[test]
    fn server_closing_each_time() {
        let (addr, tls, accepted) = fake_server(true);
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
        for id in 1..=3u16 {
            assert_eq!(dns::id(&doh.resolve(&dns::tests::query(id, None)).unwrap()), Some(id));
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn wrong_cert_is_refused() {
        let (addr, _tls, _) = fake_server(false);
        // trusting only the public roots, the self-signed cert must fail
        let doh = Doh::new(tls_config(public_roots()), "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
        assert!(doh.resolve(&dns::tests::query(9, None)).is_err());
    }

    #[test]
    fn dead_kept_alive_connection_recovers_fast() {
        let (addr, tls, accepted) = fake_server_with(false, "stall");
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
        assert!(doh.resolve(&dns::tests::query(1, None)).is_ok());
        let t = Instant::now();
        assert!(doh.resolve(&dns::tests::query(2, None)).is_ok(), "falls back to a fresh connection");
        assert!(t.elapsed() < Duration::from_millis(3500), "gave up on the dead connection after ~2 s, took {:?}", t.elapsed());
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invalid_answers_are_rejected() {
        for bad in ["ctype", "question", "id"] {
            let (addr, tls, _) = fake_server_with(false, bad);
            let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![addr]).unwrap();
            assert!(doh.resolve(&dns::tests::query(3, None)).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn dead_server_fails_over() {
        let (addr, tls, _) = fake_server(false);
        // first address refuses connections, second works
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![dead, addr]).unwrap();
        assert!(doh.resolve(&dns::tests::query(5, None)).is_ok());
    }

    /// Accepts TCP, then never says anything (TLS stalls).
    fn silent_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut keep = vec![];
            for t in l.incoming().flatten() {
                keep.push(t);
            }
        });
        a
    }

    #[test]
    fn broken_first_server_falls_back_after_tcp_connects() {
        // review N-15: TCP works on the first address, but TLS / HTTP / the
        // certificate doesn't - the second address must still be used
        let io = Duration::from_millis(600);
        let (good, tls, _) = fake_server(false);
        let (http503, _, _) = fake_server_with(false, "503");
        let bad_cert = fake_server_own_cert(); // not trusted by `tls`
        for (first, what) in [(silent_server(), "TLS stall"), (http503, "HTTP 503"), (bad_cert, "bad certificate")] {
            let doh = Doh::new(tls.clone(), "dns.nextdns.io", "/abc123/test-pc", vec![first, good])
                .unwrap()
                .with_timeouts(io, Duration::from_secs(4));
            let t = Instant::now();
            assert!(doh.resolve(&dns::tests::query(7, None)).is_ok(), "{what}: second address used");
            assert!(t.elapsed() < io * 3, "{what}: bounded ({:?})", t.elapsed());
            doh.reset();
            let t = Instant::now();
            assert!(doh.resolve(&dns::tests::query(8, None)).is_ok());
            assert!(t.elapsed() < io, "{what}: the good address is tried first next time ({:?})", t.elapsed());
        }
        // the 503 case really got as far as HTTP (same certificate as `good`)
        let (only503, _, _) = fake_server_with(false, "503");
        let e = Doh::new(tls.clone(), "dns.nextdns.io", "/abc123/test-pc", vec![only503])
            .unwrap()
            .resolve(&dns::tests::query(7, None))
            .unwrap_err();
        assert!(e.contains("503"), "{e}");
        // all addresses bad: one bounded failure naming each, the cert one marked
        let c1 = fake_server_own_cert();
        let doh = Doh::new(tls.clone(), "dns.nextdns.io", "/abc123/test-pc", vec![silent_server(), c1])
            .unwrap()
            .with_timeouts(io, Duration::from_secs(4));
        let t = Instant::now();
        let e = doh.resolve(&dns::tests::query(9, None)).unwrap_err();
        assert!(e.contains("TLS handshake failed") && e.contains("certificate") && e.contains("NOT valid"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        // a server that answers one byte at a time can't stretch the lookup
        // past the deadline, nor eat the next address's share (review V3-07)
        let (drip, _, _) = fake_server_with(false, "drip");
        let doh =
            Doh::new(tls.clone(), "dns.nextdns.io", "/abc123/test-pc", vec![drip]).unwrap().with_timeouts(io, Duration::from_millis(1500));
        let t = Instant::now();
        let e = doh.resolve(&dns::tests::query(9, None)).unwrap_err();
        assert!(e.contains("deadline") || e.contains("unavailable") || e.contains("timed out"), "{e}");
        assert!(t.elapsed() < Duration::from_millis(1900), "slow drip cut off at the deadline ({:?})", t.elapsed());
        let (drip, _, _) = fake_server_with(false, "drip");
        let doh =
            Doh::new(tls.clone(), "dns.nextdns.io", "/abc123/test-pc", vec![drip, good]).unwrap().with_timeouts(io, Duration::from_secs(3));
        let t = Instant::now();
        assert!(doh.resolve(&dns::tests::query(9, None)).is_ok(), "the second address still gets its share");
        assert!(t.elapsed() < Duration::from_millis(3300), "{:?}", t.elapsed());
        // the overall deadline caps the time even with many dead addresses
        let many: Vec<SocketAddr> = (0..6).map(|_| silent_server()).collect();
        let doh = Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", many).unwrap().with_timeouts(io, Duration::from_millis(1500));
        let t = Instant::now();
        assert!(doh.resolve(&dns::tests::query(9, None)).is_err());
        assert!(t.elapsed() < Duration::from_millis(2300), "deadline respected ({:?})", t.elapsed());
    }
}
