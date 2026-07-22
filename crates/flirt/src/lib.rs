//! FLIRT — Fast Library Identification and Recognition, from scratch.
//!
//! Names statically-linked / template-instantiated library functions (CRT, STL)
//! in a stripped binary by matching each unnamed function's relocation-masked
//! byte signature against a database built offline from the toolchain's static
//! libraries (`libcmt.lib`, `libcpmt.lib`, `libucrt.lib`, `libstdc++.a`, ...).

pub mod ar;
pub mod coff;
pub mod elf;
pub mod gen;
pub mod rich;
pub mod sig;

pub use sig::{deserialize, serialize, FuncSig, SigDb};

/// Load every `*.fdb` signature database in a directory.
pub fn load_dir(dir: &std::path::Path) -> Vec<SigDb> {
    let mut dbs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("fdb") {
                if let Ok(buf) = std::fs::read(&p) {
                    if let Some(db) = deserialize(&buf) {
                        dbs.push(db);
                    }
                }
            }
        }
    }
    dbs
}
