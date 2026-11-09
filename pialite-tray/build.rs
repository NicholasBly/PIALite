fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI failed to compile");
    windows_resources("PIA Lite tray", Some("../assets/pialite.ico"));
}

/// Version information (and the icon) inside the .exe on Windows builds.
fn windows_resources(description: &str, icon: Option<&str>) {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "PIA Lite").set("FileDescription", description).set("LegalCopyright", "GPL-3.0-or-later");
    if let Some(i) = icon {
        println!("cargo:rerun-if-changed={i}");
        res.set_icon(i);
    }
    if let Err(e) = res.compile() {
        // cross-checks from Linux have no resource compiler - not fatal
        println!("cargo:warning=Windows resources not added: {e}");
    }
}
