//! Updates from GitHub releases.
//!
//!  * `check-update`  (any user; the tray runs it about once a day): is
//!    there a newer release, and is it signed?
//!  * `apply-update`  (admin): download the package for THIS kind of install
//!    (from install.json: msi / deb / rpm / tarball) into the admin-only data
//!    folder, check it against SHA256SUMS - whose ed25519 signature must match
//!    the public key built into this program - and install it. The installer
//!    keeps the features chosen before (setup reads install.json).
//!
//! An unsigned release (no signing key configured for the project) is only
//! announced; the tray then opens the download page instead.

use crate::{config, doh, sys};
use std::path::{Path, PathBuf};

pub const REPO: &str = "NicholasBly/PIALite";
/// Raw ed25519 public key, base64 - or "NONE" (releases aren't signed).
const PUBLIC_KEY: &str = include_str!("../../keys/release-signing.pub");
const MAX_API: usize = 2 * 1024 * 1024;
const MAX_ASSET: usize = 64 * 1024 * 1024;
/// A package install (it runs setup, which waits for the guard) may take a while.
#[cfg_attr(windows, allow(dead_code))]
const PACKAGE_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq)]
pub struct Asset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub page: String,
    pub assets: Vec<Asset>,
}

impl Release {
    fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
    pub fn signed(&self) -> bool {
        public_key().is_some() && self.asset("SHA256SUMS").is_some() && self.asset("SHA256SUMS.sig").is_some()
    }
}

pub fn public_key() -> Option<[u8; 32]> {
    let k = b64decode(PUBLIC_KEY.trim())?;
    k.try_into().ok()
}

/// Standard base64 (with or without padding); None if malformed.
pub fn b64decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let data: &[u8] = match bytes.iter().position(|&c| c == b'=') {
        Some(p) if bytes[p..].iter().all(|&c| c == b'=') && bytes.len() - p <= 2 => &bytes[..p],
        Some(_) => return None,
        None => &bytes,
    };
    if data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    for chunk in data.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// "v1.2.3" / "1.2.3" -> (1, 2, 3); pre-releases ("1.2.3-rc1") are not offered.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let mut p = v.split('.');
    let t = (p.next()?.parse().ok()?, p.next()?.parse().ok()?, p.next()?.parse().ok()?);
    p.next().is_none().then_some(t)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    matches!((parse_version(candidate), parse_version(current)), (Some(a), Some(b)) if a > b)
}

/// The release JSON from GitHub's API (only the fields used).
pub fn parse_release(json: &str) -> Result<Release, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("GitHub answered something unexpected: {e}"))?;
    if v["draft"].as_bool() == Some(true) || v["prerelease"].as_bool() == Some(true) {
        return Err("the latest release is a draft or pre-release".into());
    }
    let tag = v["tag_name"].as_str().ok_or("release without a tag")?.to_string();
    let assets = v["assets"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| Some(Asset { name: x["name"].as_str()?.to_string(), url: x["browser_download_url"].as_str()?.to_string() }))
                .collect()
        })
        .unwrap_or_default();
    Ok(Release { version: tag.trim_start_matches('v').to_string(), page: v["html_url"].as_str().unwrap_or("").to_string(), tag, assets })
}

/// Only https, only GitHub's own hosts.
pub fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("https://").ok_or(format!("not an https address: {url:.80}"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = host.to_ascii_lowercase();
    let ok = host == "github.com" || host == "api.github.com" || host.ends_with(".githubusercontent.com");
    if !ok || host.contains(':') || host.contains('@') {
        return Err(format!("refusing to download from {host:.60}"));
    }
    Ok((host, path.to_string()))
}

/// GET with up to 5 redirects (GitHub sends downloads to its storage host).
fn fetch(url: &str, max: usize) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..6 {
        let (host, path) = split_url(&url)?;
        let r = doh::https_get_url(&host, &path, max)?;
        if r.status == 200 {
            return Ok(r.body);
        }
        url = if r.location.starts_with('/') { format!("https://{host}{}", r.location) } else { r.location };
    }
    Err("too many redirects".into())
}

pub fn latest() -> Result<Release, String> {
    if let Ok(path) = std::env::var("PIALITE_UPDATE_JSON") {
        // tests / offline checks
        return parse_release(&std::fs::read_to_string(path).map_err(|e| e.to_string())?);
    }
    let body = fetch(&format!("https://api.github.com/repos/{REPO}/releases/latest"), MAX_API)?;
    parse_release(&String::from_utf8_lossy(&body))
}

/// Asset file name for an install kind (names made by the release workflow).
pub fn asset_name(kind: &str, version: &str) -> Option<String> {
    Some(match kind {
        "msi" => format!("PIALite-{version}-windows-x64.msi"),
        "portable" if cfg!(windows) => format!("PIALite-{version}-windows-x64-portable.zip"),
        "portable" | "tarball" => format!("PIALite-{version}-linux-x86_64.tar.gz"),
        "deb" => format!("pialite_{version}_amd64.deb"),
        "rpm" => format!("pialite-{version}-1.x86_64.rpm"),
        _ => return None,
    })
}

/// Can this kind be updated in one click (by `apply-update`)?
pub fn one_click(kind: &str) -> bool {
    matches!(kind, "msi" | "deb" | "rpm" | "tarball")
}

/// SHA256SUMS carries a valid ed25519 signature from `key` (raw 64 bytes or base64).
fn check_signature(key: &[u8; 32], sums: &[u8], sig: &[u8]) -> Result<(), String> {
    let sig = if sig.len() == 64 {
        sig.to_vec()
    } else {
        b64decode(std::str::from_utf8(sig).map_err(|_| "bad signature file")?).ok_or("bad signature file")?
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(sums, &sig)
        .map_err(|_| "the checksum list's signature is NOT valid - not installing".to_string())
}

pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The package must be listed in SHA256SUMS with its exact hash, and
/// SHA256SUMS must carry a valid signature from `key`.
pub fn verify(key: &[u8; 32], sums: &[u8], sig: &[u8], name: &str, data: &[u8]) -> Result<(), String> {
    check_signature(key, sums, sig)?;
    let text = std::str::from_utf8(sums).map_err(|_| "checksum list is not text")?;
    let want = text
        .lines()
        .find_map(|l| {
            let (h, n) = l.split_once(char::is_whitespace)?;
            (n.trim().trim_start_matches('*') == name).then(|| h.to_ascii_lowercase())
        })
        .ok_or(format!("{name} is not in the signed checksum list"))?;
    if sha256_hex(data) != want {
        return Err(format!("{name} does not match its signed checksum - not installing"));
    }
    Ok(())
}

/// `verify-release DIR`: what the updater checks, for a whole release folder -
/// SHA256SUMS signed with the key built into THIS program, and every file it
/// lists matching its hash. The release job runs it with the packaged program
/// before publishing (review G97-06).
pub fn verify_release(dir: &std::path::Path) -> Result<(), String> {
    let key = public_key().ok_or("no release signing key is built into this program")?;
    let n = verify_folder(&key, dir)?;
    println!("OK: SHA256SUMS is signed with the key built into this program, and all {n} files listed in it match");
    Ok(())
}

fn verify_folder(key: &[u8; 32], dir: &std::path::Path) -> Result<usize, String> {
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{}: {e}", dir.join(name).display()));
    let sums = read("SHA256SUMS")?;
    let sig = read("SHA256SUMS.sig")?;
    check_signature(key, &sums, &sig)?; // the list first, before any file is read
    let text = std::str::from_utf8(&sums).map_err(|_| "SHA256SUMS is not text")?.to_string();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (_, name) = line.split_once(char::is_whitespace).ok_or(format!("unreadable line in SHA256SUMS: {line}"))?;
        let name = name.trim().trim_start_matches('*');
        verify(key, &sums, &sig, name, &read(name)?)?;
        n += 1;
    }
    if n == 0 {
        return Err("SHA256SUMS lists no files".into());
    }
    Ok(n)
}

fn current_kind() -> String {
    sys::read_record().map(|r| r.kind).unwrap_or_else(|| "source".into())
}

/// `check-update`: one line (or JSON) for the tray.
pub fn check(json: bool) -> Result<(), String> {
    let r = latest()?;
    let current = env!("CARGO_PKG_VERSION");
    let kind = current_kind();
    let newer = is_newer(&r.version, current);
    let name = asset_name(&kind, &r.version);
    let has_asset = name.as_ref().is_some_and(|n| r.asset(n).is_some());
    let auto = newer && r.signed() && one_click(&kind) && has_asset;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "current": current, "latest": r.version, "newer": newer, "signed": r.signed(),
                "one_click": auto, "kind": kind, "page": r.page,
            })
        );
    } else if newer {
        let how = if auto {
            " - run `pialite-guard apply-update` as admin, or use the tray".to_string()
        } else {
            format!(" - download: {}", r.page)
        };
        println!("PIA Lite {} is available (this is {current}){how}", r.version);
    } else {
        println!("PIA Lite {current} is up to date (latest release: {})", r.version);
    }
    Ok(())
}

fn updates_dir() -> Result<PathBuf, String> {
    sys::protect_data_dir()?;
    let d = config::data_dir().join("updates");
    let _ = std::fs::remove_dir_all(&d); // only ever the one being installed
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    Ok(d)
}

/// `apply-update` (admin): download, verify, install.
pub fn apply() -> Result<(), String> {
    if !sys::is_admin() {
        return Err("installing an update needs an administrator".into());
    }
    let r = latest()?;
    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(&r.version, current) {
        println!("Already up to date ({current}).");
        return Ok(());
    }
    let kind = current_kind();
    if !one_click(&kind) {
        return Err(format!("this {kind} install can't be updated automatically - download {} from {}", r.version, r.page));
    }
    let key = public_key().ok_or("this build has no release key - download the update from the releases page")?;
    if !r.signed() {
        return Err(format!("release {} is not signed - download it from {}", r.version, r.page));
    }
    let name = asset_name(&kind, &r.version).ok_or("unknown install kind")?;
    let asset = r.asset(&name).ok_or(format!("release {} has no {name}", r.version))?;
    println!("Downloading {name}...");
    let data = fetch(&asset.url, MAX_ASSET)?;
    let sums = fetch(&r.asset("SHA256SUMS").ok_or("no SHA256SUMS")?.url, MAX_API)?;
    let sig = fetch(&r.asset("SHA256SUMS.sig").ok_or("no SHA256SUMS.sig")?.url, 4096)?;
    verify(&key, &sums, &sig, &name, &data)?;
    let dir = updates_dir()?;
    let file = dir.join(&name);
    std::fs::write(&file, &data).map_err(|e| format!("{}: {e}", file.display()))?;
    config::log(&format!("update {} -> {} verified ({name}, sha256 {})", current, r.version, sha256_hex(&data)));
    println!("Verified (signed checksum matches). Installing {}...", r.version);
    install(&kind, &file)
}

#[cfg(windows)]
fn install(kind: &str, file: &Path) -> Result<(), String> {
    if kind != "msi" {
        return Err(format!("can't install a {kind} update here"));
    }
    // msiexec replaces this very program: run it from a copy outside the
    // install folder, after this process has ended (the tray quits too).
    let dir = file.parent().ok_or("no folder")?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let copy = dir.join("pialite-updater.exe");
    std::fs::copy(&me, &copy).map_err(|e| format!("{}: {e}", copy.display()))?;
    let log = dir.join("msiexec.log");
    use std::os::windows::process::CommandExt;
    std::process::Command::new(&copy)
        .args(["install-msi", &file.display().to_string(), &log.display().to_string()])
        .creation_flags(0x0000_0008 | 0x0800_0000) // DETACHED_PROCESS | CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("could not start the updater: {e}"))?;
    println!("The installer is running - PIA Lite restarts by itself when it's done.");
    Ok(())
}

/// The detached half on Windows: wait for the tray to close, run the MSI,
/// start the tray again for the signed-in user.
#[cfg(windows)]
pub fn install_msi(file: &str, log: &str) -> Result<(), String> {
    std::thread::sleep(std::time::Duration::from_secs(3));
    let _ = sys::run("taskkill", &["/IM", "pialite-tray.exe", "/F"]);
    let status = std::process::Command::new("msiexec")
        .args(["/i", file, "/passive", "/norestart", "/l*v", log])
        .status()
        .map_err(|e| format!("msiexec: {e}"))?;
    config::log(&format!("update: msiexec finished with {status}"));
    let tray = sys::read_record().map(|r| PathBuf::from(r.dir).join("pialite-tray.exe"));
    if let Some(t) = tray.filter(|t| t.is_file()) {
        // explorer starts it as the signed-in user, not as administrator
        let _ = std::process::Command::new("explorer.exe").arg(t).spawn();
    }
    if status.success() || status.code() == Some(3010) {
        Ok(())
    } else {
        Err(format!("the update's installer failed ({status}) - see {log}"))
    }
}

#[cfg(not(windows))]
fn install(kind: &str, file: &Path) -> Result<(), String> {
    let f = file.display().to_string();
    let (ok, out) = match kind {
        "deb" => sys::run_within("dpkg", &["-i", &f], PACKAGE_LIMIT)?,
        "rpm" => sys::run_within("rpm", &["-U", "--replacepkgs", &f], PACKAGE_LIMIT)?,
        "tarball" => {
            let dir = file.parent().ok_or("no folder")?;
            let d = dir.display().to_string();
            let (ok, out) = sys::run("tar", &["-xzf", &f, "-C", &d])?;
            if !ok {
                return Err(format!("unpacking failed: {}", out.trim()));
            }
            let script = std::fs::read_dir(dir)
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok())
                .map(|e| e.path().join("install.sh"))
                .find(|p| p.is_file())
                .ok_or("install.sh not found in the update")?;
            sys::run_within("sh", &[&script.display().to_string(), "--upgrade"], PACKAGE_LIMIT)?
        }
        _ => return Err(format!("can't install a {kind} update here")),
    };
    config::log(&format!("update install output: {}", out.trim()));
    if ok {
        println!("Updated. Restart the PIA Lite tray to use the new version.");
        Ok(())
    } else {
        Err(format!("installing the update failed: {}", out.lines().last().unwrap_or("").trim()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_release_folder_is_checked_like_the_updater_does() {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        let dir = std::env::temp_dir().join(format!("pialite-rel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.msi"), b"msi").unwrap();
        std::fs::write(dir.join("b.deb"), b"deb").unwrap();
        let sums = format!("{}  a.msi\n{}  b.deb\n", super::sha256_hex(b"msi"), super::sha256_hex(b"deb"));
        std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
        std::fs::write(dir.join("SHA256SUMS.sig"), kp.sign(sums.as_bytes()).as_ref()).unwrap();
        assert_eq!(super::verify_folder(&key, &dir), Ok(2));
        // a changed package, a changed list, another key: refused
        std::fs::write(dir.join("b.deb"), b"DEB").unwrap();
        assert!(super::verify_folder(&key, &dir).unwrap_err().contains("b.deb does not match"));
        std::fs::write(dir.join("b.deb"), b"deb").unwrap();
        std::fs::write(dir.join("SHA256SUMS"), sums.replace("a.msi", "c.msi")).unwrap();
        assert!(super::verify_folder(&key, &dir).unwrap_err().contains("NOT valid"));
        std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
        assert!(super::verify_folder(&[7u8; 32], &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn versions() {
        assert!(is_newer("v0.9.1", "0.9.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.9.10", "0.9.9"), "numbers, not text");
        assert!(!is_newer("0.9.0", "0.9.0"));
        assert!(!is_newer("0.8.9", "0.9.0"));
        assert!(!is_newer("1.0.0-rc1", "0.9.0"), "pre-releases aren't offered");
        assert!(!is_newer("garbage", "0.9.0"));
    }

    #[test]
    fn base64() {
        assert_eq!(b64decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(b64decode("AAEC/w==").unwrap(), vec![0, 1, 2, 255]);
        assert!(b64decode("a=b=").is_none());
        assert!(b64decode("abcde").is_none());
        assert!(b64decode("ab!d").is_none());
    }

    #[test]
    fn urls() {
        assert_eq!(split_url("https://api.github.com/repos/x/y").unwrap(), ("api.github.com".into(), "/repos/x/y".into()));
        assert!(split_url("https://release-assets.githubusercontent.com/a?b=c").is_ok());
        assert!(split_url("http://github.com/x").is_err(), "https only");
        assert!(split_url("https://github.com.evil.example/x").is_err());
        assert!(split_url("https://evil.example/github.com").is_err());
        assert!(split_url("https://github.com:444/x").is_err());
    }

    #[test]
    fn release_json() {
        let j = r#"{"tag_name":"v0.9.1","html_url":"https://github.com/NicholasBly/PIALite/releases/tag/v0.9.1","draft":false,"prerelease":false,
            "assets":[{"name":"SHA256SUMS","browser_download_url":"https://github.com/a/SHA256SUMS"},{"name":"pialite_0.9.1_amd64.deb","browser_download_url":"https://github.com/a/d.deb"}]}"#;
        let r = parse_release(j).unwrap();
        assert_eq!(r.version, "0.9.1");
        assert_eq!(r.assets.len(), 2);
        assert_eq!(r.asset(&asset_name("deb", "0.9.1").unwrap()).unwrap().url, "https://github.com/a/d.deb");
        assert!(!r.signed(), "no signature file");
        assert!(parse_release(r#"{"tag_name":"v1.0.0","prerelease":true}"#).is_err());
    }

    #[test]
    fn signature_and_checksum() {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        let pkg = b"package bytes";
        let sums = format!("{}  pialite_0.9.1_amd64.deb\n{}  other.rpm\n", sha256_hex(pkg), sha256_hex(b"x"));
        let sig = kp.sign(sums.as_bytes());
        assert!(verify(&key, sums.as_bytes(), sig.as_ref(), "pialite_0.9.1_amd64.deb", pkg).is_ok());
        // the signature as base64 text (openssl output encoded by the workflow)
        let b64 = {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for c in sig.as_ref().chunks(3) {
                let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
                for i in 0..4 {
                    if i <= c.len() {
                        s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        };
        assert!(verify(&key, sums.as_bytes(), b64.as_bytes(), "pialite_0.9.1_amd64.deb", pkg).is_ok());
        assert!(verify(&key, sums.as_bytes(), sig.as_ref(), "pialite_0.9.1_amd64.deb", b"tampered")
            .unwrap_err()
            .contains("does not match"));
        assert!(verify(&key, sums.as_bytes(), sig.as_ref(), "missing.msi", pkg).unwrap_err().contains("not in the signed"));
        let evil = sums.replace(&sha256_hex(pkg), &sha256_hex(b"evil"));
        assert!(verify(&key, evil.as_bytes(), sig.as_ref(), "pialite_0.9.1_amd64.deb", b"evil").unwrap_err().contains("NOT valid"));
    }
}
