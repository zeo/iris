// emit a `has_platform` cfg for the targets that have a native engine backend
// (Windows via iris-platform-win, Linux via iris-platform-linux), so the shared
// engine code gates the real integration on one predicate instead of repeating a
// windows/linux split at every call site. any other target compiles the no-op
// fallbacks and still builds.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(has_platform)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "windows" || os == "linux" {
        println!("cargo::rustc-cfg=has_platform");
    }
}
