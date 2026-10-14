fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-headerpad,0x1000");
        println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
