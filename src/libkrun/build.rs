fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let major = std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap();
    let minor = std::env::var("CARGO_PKG_VERSION_MINOR").unwrap();

    if target_os == "linux" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libkrun.so.{major}");
    } else if target_os == "macos" {
        println!(
            "cargo:rustc-cdylib-link-arg=-Wl,-install_name,libkrun.{major}.dylib,-compatibility_version,{major}.0.0,-current_version,{major}.{minor}.0"
        );
        println!("cargo:rustc-link-lib=framework=Hypervisor");
    }
}
