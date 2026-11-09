fn main() {
    println!("cargo:rerun-if-changed=../keys/release-signing.pub");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "PIA Lite")
        .set("FileDescription", "PIA Lite guard (kill switch, encrypted DNS, hotel login)")
        .set("LegalCopyright", "GPL-3.0-or-later");
    res.set_icon("../assets/pialite.ico");
    if let Err(e) = res.compile() {
        println!("cargo:warning=Windows resources not added: {e}");
    }
}
