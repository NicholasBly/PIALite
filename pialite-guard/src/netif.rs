//! Network adapters as Windows sees them - a second, independent signal next
//! to what piactl reports:
//!
//! - PIA's adapters (review V4-12, F51-07): only adapters that are clearly
//!   PIA's count - WireGuard's "wgpia0", or one whose description names
//!   Private Internet Access. Anything else is ignored, so an adapter we don't
//!   recognise can never cause a false "down" (it shows as "not found").
//! - Is there a usable network at all? (an adapter that is not PIA's, not
//!   loopback/tunnel, is up, has a gateway and a ready address that isn't
//!   link-local). PIA is asked to connect once there is one - see policy.rs.

#[derive(Clone, Debug, PartialEq)]
pub struct Adapter {
    pub name: String,
    pub up: bool,
    /// Windows' interface index (to compare with the route Windows picks).
    pub index: u32,
}

/// One look at the adapters.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Snapshot {
    /// PIA's adapters and whether each is up.
    pub pia: Vec<Adapter>,
    /// The first usable network adapter (its name), if any.
    pub network: Option<String>,
}

/// What one adapter looks like (filled in from Windows), for the rules below.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub name: String,
    pub description: String,
    pub index: u32,
    pub up: bool,
    /// Loopback or a tunnel interface type (never "the network").
    pub virtual_type: bool,
    pub has_gateway: bool,
    /// At least one address that is ready (not tentative) and not link-local.
    pub ready_address: bool,
}

/// Is this one of PIA's adapters? (FriendlyName, Description). Linux has no
/// descriptions: WireGuard's "wgpia0", or OpenVPN's "tun*" devices (marked
/// "linux-tun" by the Linux snapshot).
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
pub fn is_pia(name: &str, description: &str) -> bool {
    name.eq_ignore_ascii_case("wgpia0")
        || description.to_ascii_lowercase().contains("private internet access")
        || (description == "linux-tun" && name.starts_with("tun"))
}

/// Could traffic go out through this adapter right now?
#[cfg_attr(not(windows), allow(dead_code))]
pub fn usable_network(i: &Info) -> bool {
    !is_pia(&i.name, &i.description) && !i.virtual_type && i.up && i.has_gateway && i.ready_address
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn snapshot_of(list: &[Info]) -> Snapshot {
    Snapshot {
        pia: list
            .iter()
            .filter(|i| is_pia(&i.name, &i.description))
            .map(|i| Adapter { name: i.name.clone(), up: i.up, index: i.index })
            .collect(),
        network: list.iter().find(|i| usable_network(i)).map(|i| i.name.clone()),
    }
}

/// An address that counts: IPv4 not 169.254.x.x, IPv6 not fe80::/10.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn routable(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(a) => !a.is_link_local() && !a.is_loopback() && !a.is_unspecified(),
        std::net::IpAddr::V6(a) => (a.segments()[0] & 0xffc0) != 0xfe80 && !a.is_loopback() && !a.is_unspecified(),
    }
}

// ------------------------------------------------------------------ Linux

/// /proc/net/route: interfaces with an IPv4 default route through a gateway.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn ipv4_gateways(route: &str) -> Vec<String> {
    route
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags ... ; RTF_GATEWAY = 0x2
            let flags = u32::from_str_radix(f.get(3)?, 16).ok()?;
            (*f.get(1)? == "00000000" && *f.get(2)? != "00000000" && flags & 0x2 != 0).then(|| f[0].to_string())
        })
        .collect()
}

/// /proc/net/ipv6_route: interfaces with an IPv6 default route (::/0)
/// through a next hop.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn ipv6_gateways(route: &str) -> Vec<String> {
    let zero = "00000000000000000000000000000000";
    route
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // dest plen src splen nexthop metric refcnt use flags iface
            (f.len() >= 10 && f[0] == zero && f[1] == "00" && f[4] != zero).then(|| f[9].to_string())
        })
        .collect()
}

/// /proc/net/if_inet6: interfaces with a ready (not tentative or failed),
/// not link-local, not loopback IPv6 address.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn ipv6_ready(if_inet6: &str) -> Vec<String> {
    if_inet6
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // addr ifindex plen scope flags name; IFA_F_TENTATIVE 0x40, IFA_F_DADFAILED 0x08
            let addr = *f.first()?;
            let flags = u32::from_str_radix(f.get(4)?, 16).ok()?;
            let link_local = ["fe8", "fe9", "fea", "feb"].iter().any(|p| addr.starts_with(p));
            let loopback = addr == "00000000000000000000000000000001";
            if link_local || loopback || flags & 0x48 != 0 {
                return None;
            }
            f.get(5).map(|s| s.to_string())
        })
        .collect()
}

/// `ip -o route get ADDR`: the device the kernel would use (policy routing
/// included - PIA's WireGuard routes live in their own table).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn route_dev(ip_route_get: &str) -> Option<String> {
    let mut w = ip_route_get.split_whitespace();
    while let Some(t) = w.next() {
        if t == "dev" {
            return w.next().map(str::to_string);
        }
    }
    None
}

/// Linux: interfaces from /sys/class/net, addresses from getifaddrs and
/// /proc/net/if_inet6, gateways from /proc/net/route and ipv6_route.
#[cfg(all(target_os = "linux", not(test)))]
pub fn snapshot() -> Option<Snapshot> {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let mut gw = ipv4_gateways(&read("/proc/net/route")?);
    gw.extend(ipv6_gateways(&read("/proc/net/ipv6_route").unwrap_or_default()));
    let mut ready = ipv6_ready(&read("/proc/net/if_inet6").unwrap_or_default());
    ready.extend(ipv4_ready());
    let mut list = vec![];
    for e in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let attr = |a: &str| read(&format!("/sys/class/net/{name}/{a}")).map(|v| v.trim().to_string()).unwrap_or_default();
        let flags = u32::from_str_radix(attr("flags").trim_start_matches("0x"), 16).unwrap_or(0);
        let kind: u32 = attr("type").parse().unwrap_or(0);
        let oper = attr("operstate");
        // IFF_UP 0x1, IFF_RUNNING 0x40; tunnels report operstate "unknown"
        let up = flags & 0x1 != 0 && (flags & 0x40 != 0 || oper == "up" || oper == "unknown");
        let tun = kind == 65534; // ARPHRD_NONE: tun / WireGuard
        list.push(Info {
            description: if tun { "linux-tun".into() } else { String::new() },
            index: attr("ifindex").parse().unwrap_or(0),
            up,
            virtual_type: kind == 772 || tun, // loopback or tunnel
            has_gateway: gw.contains(&name),
            ready_address: ready.contains(&name),
            name,
        });
    }
    Some(snapshot_of(&list))
}

/// Interfaces with an IPv4 address that isn't link-local or loopback.
#[cfg(all(target_os = "linux", not(test)))]
fn ipv4_ready() -> Vec<String> {
    let mut out = vec![];
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut p = head;
    while !p.is_null() {
        let a = unsafe { &*p };
        if !a.ifa_addr.is_null() && unsafe { (*a.ifa_addr).sa_family } as i32 == libc::AF_INET {
            let sin = unsafe { &*(a.ifa_addr as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            if routable(&ip.into()) {
                out.push(unsafe { std::ffi::CStr::from_ptr(a.ifa_name) }.to_string_lossy().into_owned());
            }
        }
        p = a.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

/// Linux: the interface index the kernel would route `ip` through.
#[cfg(all(target_os = "linux", not(test)))]
pub fn route_index(ip: std::net::Ipv4Addr) -> Option<u32> {
    let ipcmd = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"].into_iter().find(|p| std::path::Path::new(p).is_file())?;
    let out = std::process::Command::new(ipcmd).args(["-o", "route", "get", &ip.to_string()]).output().ok()?;
    let dev = route_dev(&String::from_utf8_lossy(&out.stdout))?;
    std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex")).ok()?.trim().parse().ok()
}

#[cfg(all(windows, not(test)))]
pub fn snapshot() -> Option<Snapshot> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{IpDadStatePreferred, AF_INET, AF_INET6, AF_UNSPEC};

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    for _ in 0..3 {
        // u64 elements: the buffer is suitably aligned for the structures
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let first = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), first, &mut size) };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            return None;
        }
        let text = |p: *mut u16| -> String {
            if p.is_null() {
                return String::new();
            }
            let mut n = 0;
            while unsafe { *p.add(n) } != 0 && n < 512 {
                n += 1;
            }
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
        };
        let mut list = vec![];
        let mut a = first;
        while !a.is_null() {
            let r = unsafe { &*a };
            let mut ready_address = false;
            let mut u = r.FirstUnicastAddress;
            while !u.is_null() {
                let ua = unsafe { &*u };
                let sa = ua.Address.lpSockaddr as *const u8;
                let len = ua.Address.iSockaddrLength.max(0) as usize;
                if !sa.is_null() && len >= 8 && ua.DadState == IpDadStatePreferred {
                    // raw sockaddr bytes: family (2), port (2), then the address
                    let b = unsafe { std::slice::from_raw_parts(sa, len) };
                    let family = u16::from_ne_bytes([b[0], b[1]]);
                    let ip = if family == AF_INET {
                        Some(std::net::IpAddr::from([b[4], b[5], b[6], b[7]]))
                    } else if family == AF_INET6 && len >= 24 {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&b[8..24]);
                        Some(std::net::IpAddr::from(o))
                    } else {
                        None
                    };
                    if ip.is_some_and(|ip| routable(&ip)) {
                        ready_address = true;
                    }
                }
                u = ua.Next;
            }
            list.push(Info {
                name: text(r.FriendlyName),
                description: text(r.Description),
                index: unsafe { r.Anonymous1.Anonymous.IfIndex },
                up: r.OperStatus == IfOperStatusUp,
                virtual_type: r.IfType == IF_TYPE_SOFTWARE_LOOPBACK || r.IfType == IF_TYPE_TUNNEL,
                has_gateway: !r.FirstGatewayAddress.is_null(),
                ready_address,
            });
            a = r.Next;
        }
        return Some(snapshot_of(&list));
    }
    None
}

/// Elsewhere (tests): a stand-in. By default Wi-Fi is up and PIA's "wgpia0"
/// is up; tests change that or make the look fail.
#[cfg(any(test, not(any(windows, target_os = "linux"))))]
#[cfg_attr(not(test), allow(dead_code))]
enum TestNet {
    Default,
    Fail,
    Set(Snapshot),
}

/// The interface Windows would send traffic to `ip` through (information
/// only, review V60-08: does the route really go through PIA's adapter?).
#[cfg(all(windows, not(test)))]
pub fn route_index(ip: std::net::Ipv4Addr) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let mut idx = 0u32;
    // IPAddr is in network byte order: the octets as they are, in memory
    let rc = unsafe { GetBestInterface(u32::from_ne_bytes(ip.octets()), &mut idx) };
    (rc == 0).then_some(idx)
}

#[cfg(any(test, not(any(windows, target_os = "linux"))))]
static TEST_ROUTE: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(Some(7));

/// Elsewhere (tests): through "wgpia0" (index 7) unless a test says otherwise.
#[cfg(any(test, not(any(windows, target_os = "linux"))))]
pub fn route_index(_ip: std::net::Ipv4Addr) -> Option<u32> {
    *TEST_ROUTE.lock().unwrap()
}

#[cfg(all(test, not(windows)))]
pub fn set_test_route(v: Option<u32>) {
    *TEST_ROUTE.lock().unwrap() = v;
}

#[cfg(any(test, not(any(windows, target_os = "linux"))))]
static TEST_NET: std::sync::Mutex<TestNet> = std::sync::Mutex::new(TestNet::Default);

#[cfg(any(test, not(any(windows, target_os = "linux"))))]
pub fn snapshot() -> Option<Snapshot> {
    match &*TEST_NET.lock().unwrap() {
        TestNet::Default => {
            Some(Snapshot { pia: vec![Adapter { name: "wgpia0".into(), up: true, index: 7 }], network: Some("Wi-Fi".into()) })
        }
        TestNet::Fail => None,
        TestNet::Set(s) => Some(s.clone()),
    }
}

/// Tests: PIA's adapters as given (plus Wi-Fi up); None = the look fails.
#[cfg(all(test, not(windows)))]
pub fn set_test_adapters(v: Option<Vec<Adapter>>) {
    *TEST_NET.lock().unwrap() = match v {
        None => TestNet::Fail,
        Some(pia) => TestNet::Set(Snapshot { pia, network: Some("Wi-Fi".into()) }),
    };
}

#[cfg(all(test, not(windows)))]
pub fn set_test_snapshot(v: Snapshot) {
    *TEST_NET.lock().unwrap() = TestNet::Set(v);
}

#[cfg(all(test, not(windows)))]
pub fn reset_test_net() {
    *TEST_NET.lock().unwrap() = TestNet::Default;
    *TEST_ROUTE.lock().unwrap() = Some(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux parsing: default routes, ready IPv6 addresses, the routed device.
    #[test]
    fn linux_proc_files() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                     wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n\
                     docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert_eq!(ipv4_gateways(route), vec!["wlan0"]);
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
                  20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert_eq!(ipv6_gateways(v6), vec!["eth0"], "only a default route with a next hop");
        let inet6 = "20010db8000000000000000000000005 02 40 00 00 eth0\n\
                     fe800000000000000000000000000005 02 40 20 80 eth0\n\
                     20010db8000000000000000000000006 03 40 00 40 wlan0\n\
                     00000000000000000000000000000001 01 80 10 80 lo\n";
        assert_eq!(ipv6_ready(inet6), vec!["eth0"], "not link-local, not tentative, not loopback");
        assert_eq!(route_dev("45.90.28.0 dev wgpia0 table 51820 src 10.1.2.3 uid 0 \\    cache"), Some("wgpia0".into()));
        assert_eq!(route_dev("garbage"), None);
        assert!(is_pia("tun0", "linux-tun") && !is_pia("tun0", "") && !is_pia("eth0", "linux-tun"));
    }

    #[test]
    fn only_pia_adapters_count() {
        assert!(is_pia("wgpia0", "WireGuard Tunnel"));
        assert!(is_pia("Ethernet 3", "Private Internet Access Network Adapter"));
        assert!(!is_pia("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz"));
        assert!(!is_pia("wg0", "WireGuard Tunnel"), "someone else's WireGuard isn't PIA's");
    }

    #[test]
    fn what_counts_as_a_usable_network() {
        let wifi = Info { name: "Wi-Fi".into(), up: true, has_gateway: true, ready_address: true, ..Default::default() };
        assert!(usable_network(&wifi));
        assert!(!usable_network(&Info { up: false, ..wifi.clone() }), "down");
        assert!(!usable_network(&Info { has_gateway: false, ..wifi.clone() }), "no gateway (e.g. WSL/Hyper-V internal)");
        assert!(!usable_network(&Info { ready_address: false, ..wifi.clone() }), "only a link-local or tentative address");
        assert!(!usable_network(&Info { virtual_type: true, ..wifi.clone() }), "loopback / tunnel interface");
        assert!(!usable_network(&Info { name: "wgpia0".into(), ..wifi.clone() }), "PIA's own adapter is not 'the network'");
        let s = snapshot_of(&[Info { name: "wgpia0".into(), up: true, index: 7, ..Default::default() }, wifi]);
        assert_eq!(s.pia, vec![Adapter { name: "wgpia0".into(), up: true, index: 7 }]);
        assert_eq!(s.network.as_deref(), Some("Wi-Fi"));
        assert!(routable(&"192.168.1.20".parse().unwrap()));
        assert!(!routable(&"169.254.3.4".parse().unwrap()));
        assert!(routable(&"2a02:1:2::5".parse().unwrap()));
        assert!(!routable(&"fe80::1".parse().unwrap()));
    }
}
