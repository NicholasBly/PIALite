//! Local DNS server on 127.0.0.1:53 (UDP + TCP). Every query is sent on to
//! NextDNS over DoH. If NextDNS can't be reached the answer is SERVFAIL -
//! never a fallback to plain, unencrypted DNS.

use crate::doh::Resolve;
use crate::{config::log, dns};
use pialite_common::status::{DnsHealth, DnsStatus};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

const WORKERS: usize = 8;
const MAX_TCP_CLIENTS: usize = 32;
const QUEUE_MAX: usize = 256;

/// Outcomes remembered for the health rating.
const RECENT: usize = 20;
/// Names remembered (as keyed hashes only) for the "did Windows really ask
/// us?" check (review N-11).
const NAMES: usize = 256;

#[derive(Default)]
pub struct Stats {
    pub answered: AtomicU64,
    pub failed: AtomicU64,
    pub overloaded: AtomicU64,
    pub malformed: AtomicU64,
    recent: Mutex<VecDeque<bool>>,
    last_ok: Mutex<Option<Instant>>,
    last_error: Mutex<String>,
    last_ms: AtomicU64,
    pub listening: AtomicBool,
    bind_error: Mutex<String>,
    /// Recent query names, stored only as hashes with a random per-run key:
    /// no readable lookup history is kept.
    names: Mutex<VecDeque<u64>>,
    key: std::hash::RandomState,
}

impl Stats {
    fn record(&self, ok: bool) {
        let mut r = self.recent.lock().unwrap();
        if r.len() == RECENT {
            r.pop_front();
        }
        r.push_back(ok);
    }

    fn name_hash(&self, name: &str) -> u64 {
        use std::hash::BuildHasher;
        self.key.hash_one(name.trim_end_matches('.').to_ascii_lowercase())
    }

    fn note_name(&self, query: &[u8]) {
        if let Some(n) = dns::qname(query) {
            let h = self.name_hash(&n);
            let mut r = self.names.lock().unwrap();
            if r.len() == NAMES {
                r.pop_front();
            }
            r.push_back(h);
        }
    }

    /// Did a query for `name` reach the proxy recently?
    pub fn seen(&self, name: &str) -> bool {
        let h = self.name_hash(name);
        self.names.lock().unwrap().contains(&h)
    }

    /// Judged over the last 20 lookups, not just one (audit P2-21).
    pub fn health(&self) -> DnsHealth {
        let r = self.recent.lock().unwrap();
        match r.back() {
            None => DnsHealth::Untested,
            // "down" only when the last 3 lookups all failed; one blip is "degraded"
            Some(false) if r.len() >= 3 && r.iter().rev().take(3).all(|&x| !x) => DnsHealth::Down,
            Some(false) => DnsHealth::Degraded,
            Some(true) if r.iter().all(|&x| x) => DnsHealth::Ok,
            Some(true) => DnsHealth::Degraded,
        }
    }

    pub fn snapshot(&self) -> DnsStatus {
        DnsStatus {
            listening: self.listening.load(Ordering::Relaxed),
            bind_error: self.bind_error.lock().unwrap().clone(),
            health: self.health(),
            last_error: self.last_error.lock().unwrap().clone(),
            last_ms: self.last_ms.load(Ordering::Relaxed),
            last_ok_age: self.last_ok.lock().unwrap().map(|t| t.elapsed().as_secs()),
            answered: self.answered.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            overloaded: self.overloaded.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
        }
    }
}

/// The resolver can be swapped (new profile ID) without restarting listeners.
pub type Shared = Arc<RwLock<Arc<dyn Resolve>>>;

pub struct Proxy {
    pub stats: Arc<Stats>,
    pub resolver: Shared,
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
}

fn answer(resolver: &Shared, stats: &Stats, query: &[u8]) -> Vec<u8> {
    stats.note_name(query);
    let r = resolver.read().unwrap().clone();
    let t = Instant::now();
    match r.resolve(query) {
        Ok(a) => {
            stats.answered.fetch_add(1, Ordering::Relaxed);
            stats.record(true);
            stats.last_ms.store(t.elapsed().as_millis() as u64, Ordering::Relaxed);
            *stats.last_ok.lock().unwrap() = Some(Instant::now());
            a
        }
        Err(e) => {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            stats.record(false);
            let mut last = stats.last_error.lock().unwrap();
            if *last != e {
                log(&format!("DoH lookup failed: {e}"));
                *last = e;
            }
            dns::servfail(query)
        }
    }
}

impl Proxy {
    /// Encrypted DNS turned off (0.9 feature choice): nothing listens on port
    /// 53; the status says why.
    pub fn off(addr: SocketAddr, resolver: Arc<dyn Resolve>) -> Proxy {
        let p = Proxy {
            stats: Arc::new(Stats::default()),
            resolver: Arc::new(RwLock::new(resolver)),
            stop: Arc::new(AtomicBool::new(true)),
            addr,
        };
        *p.stats.bind_error.lock().unwrap() = "encrypted DNS is turned off (installer option)".into();
        p
    }

    pub fn start(addr: SocketAddr, resolver: Arc<dyn Resolve>) -> Proxy {
        let p = Proxy {
            stats: Arc::new(Stats::default()),
            resolver: Arc::new(RwLock::new(resolver)),
            stop: Arc::new(AtomicBool::new(false)),
            addr,
        };
        let (stats, resolver, stop) = (p.stats.clone(), p.resolver.clone(), p.stop.clone());
        std::thread::spawn(move || {
            // Port 53 may be busy for a moment (e.g. the old NextDNS app is
            // still shutting down) - keep trying.
            let mut warned = false;
            let (udp, tcp) = loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                match (UdpSocket::bind(addr), TcpListener::bind(addr)) {
                    (Ok(u), Ok(t)) => break (u, t),
                    (u, t) => {
                        let e = u.err().or(t.err()).map(|e| e.to_string()).unwrap_or_default();
                        if !warned {
                            log(&format!("can't listen on {addr} yet ({e}) - retrying every 5s"));
                            warned = true;
                        }
                        *stats.bind_error.lock().unwrap() = e;
                        std::thread::sleep(Duration::from_secs(5));
                    }
                }
            };
            stats.bind_error.lock().unwrap().clear();
            stats.listening.store(true, Ordering::Relaxed);
            log(&format!("DNS proxy listening on {addr} (UDP+TCP)"));
            spawn_tcp(tcp, resolver.clone(), stats.clone(), stop.clone());
            run_udp(udp, resolver, stats, stop);
        });
        p
    }

    /// Network changed: drop kept-alive upstream connections.
    pub fn reset(&self) {
        self.resolver.read().unwrap().reset();
    }

    /// The VPN just connected: open a NextDNS connection in the background,
    /// so the first lookup (a browser starting) doesn't wait for the handshake.
    pub fn warm(&self) {
        let r = self.resolver.read().unwrap().clone();
        std::thread::spawn(move || r.warm());
    }

    pub fn set_resolver(&self, r: Arc<dyn Resolve>) {
        *self.resolver.write().unwrap() = r;
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // wake the blocking accept()/recv() calls
        let _ = UdpSocket::bind("127.0.0.1:0").and_then(|s| s.send_to(&[0], self.addr));
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

fn run_udp(udp: UdpSocket, resolver: Shared, stats: Arc<Stats>, stop: Arc<AtomicBool>) {
    let udp = Arc::new(udp);
    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, SocketAddr)>(QUEUE_MAX);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let (rx, udp, resolver, stats) = (rx.clone(), udp.clone(), resolver.clone(), stats.clone());
        std::thread::spawn(move || loop {
            let job = rx.lock().unwrap().recv();
            let Ok((query, from)) = job else { return };
            let mut reply = answer(&resolver, &stats, &query);
            if reply.len() > dns::udp_limit(&query) {
                reply = dns::truncated(&reply); // client will retry over TCP
            }
            let _ = udp.send_to(&reply, from);
        });
    }
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        match udp.recv_from(&mut buf) {
            Ok((n, from)) => {
                let q = &buf[..n];
                if !dns::is_query(q) {
                    stats.malformed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if tx.try_send((q.to_vec(), from)).is_err() {
                    // overloaded: answer SERVFAIL straight away rather than queue forever
                    stats.overloaded.fetch_add(1, Ordering::Relaxed);
                    let _ = udp.send_to(&dns::servfail(q), from);
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn spawn_tcp(listener: TcpListener, resolver: Shared, stats: Arc<Stats>, stop: Arc<AtomicBool>) {
    let clients = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(mut s) = stream else { continue };
            if clients.load(Ordering::Relaxed) >= MAX_TCP_CLIENTS {
                continue; // dropped
            }
            clients.fetch_add(1, Ordering::Relaxed);
            let (resolver, stats, clients) = (resolver.clone(), stats.clone(), clients.clone());
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
                loop {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).is_err() {
                        break;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if n < dns::HEADER || s.read_exact(&mut q).is_err() || !dns::is_query(&q) {
                        stats.malformed.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    let mut a = answer(&resolver, &stats, &q);
                    if a.len() > dns::MAX_MESSAGE {
                        a = dns::servfail(&q); // can't be framed in 16 bits (audit P2-16)
                    }
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    if s.write_all(&out).is_err() {
                        break;
                    }
                }
                clients.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers with the query + `extra` padding bytes (QR set), or fails.
    struct Fake {
        extra: usize,
        fail: bool,
    }
    impl Resolve for Fake {
        fn resolve(&self, q: &[u8]) -> Result<Vec<u8>, String> {
            if self.fail {
                return Err("offline".into());
            }
            let mut a = q.to_vec();
            a[2] |= 0x80;
            a.extend(vec![0u8; self.extra]);
            Ok(a)
        }
    }

    fn free_addr() -> SocketAddr {
        // a port free for both UDP and TCP
        loop {
            let t = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = t.local_addr().unwrap();
            drop(t);
            if UdpSocket::bind(a).is_ok() {
                return a;
            }
        }
    }

    fn wait_listening(p: &Proxy) {
        for _ in 0..200 {
            if p.stats.listening.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("proxy never listened");
    }

    fn udp_ask(addr: SocketAddr, q: &[u8]) -> Vec<u8> {
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.send_to(q, addr).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = c.recv_from(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn udp_tcp_truncation_servfail() {
        let addr = free_addr();
        let p = Proxy::start(addr, Arc::new(Fake { extra: 0, fail: false }));
        wait_listening(&p);

        let q = dns::tests::query(0x7777, None);
        let a = udp_ask(addr, &q);
        assert_eq!(dns::id(&a), Some(0x7777));
        assert_eq!(a[2] & 0x80, 0x80);

        // names that reached the proxy can be confirmed later (hashed, review N-11)
        assert!(!p.stats.seen("probe-1a2b.pialite.test"));
        udp_ask(addr, &dns::build_query(9, "Probe-1A2B.pialite.test", 1).unwrap());
        assert!(p.stats.seen("probe-1a2b.pialite.test.") && p.stats.seen("PROBE-1a2b.pialite.test"));
        assert!(!p.stats.seen("probe-other.pialite.test"));
        assert_eq!(dns::qname(&dns::build_query(1, "A.b.C", 1).unwrap()).as_deref(), Some("a.b.c"));

        // big answer: over UDP it's truncated (TC bit), over TCP it's whole
        p.set_resolver(Arc::new(Fake { extra: 1000, fail: false }));
        let a = udp_ask(addr, &q);
        assert_eq!(a[2] & 0x02, 0x02, "TC bit");
        assert!(a.len() <= 512);
        // ...unless the client said (EDNS) it accepts big UDP answers
        let a = udp_ask(addr, &dns::tests::query(1, Some(1232)));
        assert_eq!(a[2] & 0x02, 0, "no TC with EDNS 1232");

        let mut t = TcpStream::connect(addr).unwrap();
        for _ in 0..2 {
            let mut msg = (q.len() as u16).to_be_bytes().to_vec();
            msg.extend_from_slice(&q);
            t.write_all(&msg).unwrap();
            let mut len = [0u8; 2];
            t.read_exact(&mut len).unwrap();
            let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
            t.read_exact(&mut a).unwrap();
            assert_eq!(a.len(), q.len() + 1000);
        }

        // NextDNS unreachable -> SERVFAIL, never plain DNS
        p.set_resolver(Arc::new(Fake { extra: 0, fail: true }));
        let a = udp_ask(addr, &q);
        assert_eq!(a[3] & 0x0F, 2);
        assert_eq!(p.stats.health(), DnsHealth::Degraded, "one failure is a blip, not 'down'");
        udp_ask(addr, &q);
        udp_ask(addr, &q);
        assert_eq!(p.stats.health(), DnsHealth::Down, "three in a row is 'down'");
        assert!(p.stats.failed.load(Ordering::Relaxed) >= 1);
        // back up -> degraded (recent failures), not instantly "ok"
        p.set_resolver(Arc::new(Fake { extra: 0, fail: false }));
        udp_ask(addr, &q);
        assert_eq!(p.stats.health(), DnsHealth::Degraded);
        // garbage is counted, not answered
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.send_to(b"hello", addr).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(p.stats.malformed.load(Ordering::Relaxed) >= 1);
        p.stop();
    }

    #[test]
    fn end_to_end_with_tls() {
        // local DNS proxy -> real TLS to the fake NextDNS server
        let (srv, tls, _) = crate::doh::tests::fake_server(false);
        let doh = crate::doh::Doh::new(tls, "dns.nextdns.io", "/abc123/test-pc", vec![srv]).unwrap();
        let addr = free_addr();
        let p = Proxy::start(addr, Arc::new(doh));
        wait_listening(&p);
        let a = udp_ask(addr, &dns::tests::query(0xABCD, None));
        assert_eq!(dns::id(&a), Some(0xABCD));
        assert_eq!(p.stats.health(), DnsHealth::Ok);
        p.stop();
    }
}
