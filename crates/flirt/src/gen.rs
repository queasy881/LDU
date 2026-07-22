//! Signature-database generation: read static libraries and emit `FuncSig`s.

use crate::{ar, coff, elf, sig};
use std::collections::HashSet;
use std::path::Path;

/// Build signatures from a set of static-library files (`.lib` / `.a`). COFF and
/// ELF members are dispatched by their magic. Exact duplicates are dropped.
pub fn generate(lib_paths: &[std::path::PathBuf]) -> Vec<sig::FuncSig> {
    let mut sigs: Vec<sig::FuncSig> = Vec::new();
    let mut seen: HashSet<(String, u32, u16, u32)> = HashSet::new();
    for path in lib_paths {
        let buf = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for m in ar::members(&buf) {
            let funcs = if m.data.starts_with(&[0x7f, b'E', b'L', b'F']) {
                elf::functions(m.data)
            } else {
                coff::functions(m.data)
            };
            for f in funcs {
                // skip compiler-generated thunks/labels with empty or `$` local names
                if f.name.is_empty() || f.name.starts_with('$') {
                    continue;
                }
                if let Some(s) = sig::make_sig(&f.name, &f.code, &f.variant, f.refs) {
                    let key = (s.name.clone(), s.full_len, s.crc, s.mask);
                    if seen.insert(key) {
                        sigs.push(s);
                    }
                }
            }
        }
    }
    sigs
}

/// Convenience: generate + serialize to a `.fdb` file.
pub fn generate_to(toolchain: &str, lib_paths: &[std::path::PathBuf], out: &Path) -> std::io::Result<usize> {
    let sigs = generate(lib_paths);
    let bytes = sig::serialize(toolchain, &sigs);
    std::fs::write(out, &bytes)?;
    Ok(sigs.len())
}
