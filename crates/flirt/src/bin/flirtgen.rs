//! flirtgen — build a FLIRT signature database from static libraries.
//!
//! Usage: flirtgen <toolchain-id> <out.fdb> <lib1> [lib2 ...]
//! e.g.   flirtgen msvc2026-x64 sigs/msvc2026-x64.fdb libcmt.lib libcpmt.lib libucrt.lib

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: flirtgen <toolchain-id> <out.fdb> <lib1> [lib2 ...]");
        std::process::exit(2);
    }
    let toolchain = &args[1];
    let out = PathBuf::from(&args[2]);
    let libs: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();

    let sigs = flirt::gen::generate(&libs);
    let bytes = flirt::sig::serialize(toolchain, &sigs);
    match std::fs::write(&out, &bytes) {
        Ok(()) => {
            eprintln!(
                "flirtgen: {} signatures from {} lib(s) -> {} ({} bytes)",
                sigs.len(),
                libs.len(),
                out.display(),
                bytes.len()
            );
        }
        Err(e) => {
            eprintln!("flirtgen: write {}: {e}", out.display());
            std::process::exit(1);
        }
    }
}
