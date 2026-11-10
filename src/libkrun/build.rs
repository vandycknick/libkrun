fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=Hypervisor");
    }

    let major = std::env::var("CARGO_PKG_VERSION_MAJOR")?;
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libkrun.so.{major}");
    #[cfg(target_os = "macos")]
    {
        let minor = std::env::var("CARGO_PKG_VERSION_MINOR")?;
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-install_name,libkrun.{major}.dylib,-compatibility_version,{major}.0.0,-current_version,{major}.{minor}.0"
        );
    }
    Ok(())
}
