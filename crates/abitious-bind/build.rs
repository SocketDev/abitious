//! Link setup for the binder's declared `napi_*` host symbols.
//!
//! Node resolves N-API from the host process at `dlopen`. The three platforms need
//! different link treatment:
//! - macOS: allow undefined symbols at link time (`-undefined dynamic_lookup`) - the
//!   same flag node-gyp uses for every addon.
//! - Linux (glibc + musl): shared objects keep undefined symbols by default; nothing
//!   to add.
//! - Windows: a DLL cannot carry undefined symbols. Link `node.lib` (the import
//!   library for `node.exe`, published beside `node.exe` in the win-<arch> dist
//!   folders). CI points `NODE_LIB_DIR` at the downloaded copy for the matrix' arch.
fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target.as_str() {
        "macos" => {
            println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
        }
        "windows" => {
            let lib_dir = std::env::var_os("NODE_LIB_DIR").expect(
                "NODE_LIB_DIR must point at the folder holding node.lib for the target arch",
            );
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_string_lossy()
            );
            println!("cargo:rustc-link-lib=dylib=node");
        }
        // Linux and friends: nothing to do.
        _ => {}
    }
}
