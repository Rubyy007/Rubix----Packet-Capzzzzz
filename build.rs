// build.rs — sits next to Cargo.toml, NOT inside src/
fn main() {
    #[cfg(target_os = "windows")]
    {
        println!(r"cargo:rustc-link-search=D:\download\Lib\x64");
        println!("cargo:rustc-link-lib=wpcap");
        println!("cargo:rustc-link-lib=Packet");
    }
}