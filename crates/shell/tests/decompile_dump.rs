//! Dumps decompiled pseudo-C for every exported function of each corpus DLL to
//! _qa/decomp/<dll>.c, plus a manifest, for the behavioral-equivalence harness.
//!
//! Run: cargo test -p disasmstudio --test decompile_dump -- --nocapture

use std::fmt::Write as _;

use binparser::{Arch as PArch, BinaryMeta};
use bridge::{Arch as BArch, Engine};

fn map_arch(a: PArch) -> BArch {
    match a {
        PArch::X86 => BArch::X86,
        PArch::X64 => BArch::X64,
        PArch::Arm => BArch::Arm,
        PArch::Arm64 => BArch::Arm64,
        PArch::Unknown => BArch::X64,
    }
}

#[test]
fn dump_decompiled_corpus() {
    let base = r"C:\Users\User\Downloads\sd\_qa";
    let outdir = format!("{base}\\decomp");
    let _ = std::fs::create_dir_all(&outdir);

    let mut dlls: Vec<String> = std::fs::read_dir(format!("{base}\\corpus"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("dll") {
                        p.file_stem().and_then(|s| s.to_str()).map(String::from)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    dlls.sort();
    for stem in &dlls {
        let dll = format!("{base}\\corpus\\{stem}.dll");
        if !std::path::Path::new(&dll).exists() {
            continue;
        }
        let bytes = std::fs::read(&dll).expect("read dll");
        let parsed = BinaryMeta::parse(&bytes).expect("parse");
        let image = parsed.build_image(&bytes);
        let mut engine = Engine::new(image, parsed.base, map_arch(parsed.arch));
        engine.set_is_dll(parsed.is_dll);
        engine.set_entry_rva(parsed.entry);
        for seg in &parsed.segments {
            engine.add_segment(&seg.name, seg.rva, seg.vsize, seg.flags);
        }
        for exp in &parsed.exports {
            engine.add_symbol(exp.rva, &exp.name);
            engine.add_entry(exp.rva);
        }
        engine.add_entry(parsed.entry);
        for imp in &parsed.imports {
            engine.add_import(imp.rva, &imp.name);
        }
        engine.disassemble().expect("disasm");
        engine.build_cfg().expect("cfg");
        engine.resolve_symbols().expect("symbols");
        engine.build_xrefs().expect("xrefs");

        let mut out = String::new();
        let mut manifest = String::new();
        let mut count = 0;
        let mut exps = parsed.exports.clone();
        exps.sort_by_key(|e| e.rva);
        // Track every rva already emitted so internal helpers are emitted once.
        let mut emitted: std::collections::HashSet<u64> =
            exps.iter().map(|e| e.rva).collect();
        for e in &exps {
            let code = engine.decompile(e.rva).unwrap_or_default();
            if code.trim().is_empty() {
                continue;
            }
            let _ = writeln!(out, "/* ==== {} @ {:#x} ==== */", e.name, e.rva);
            let _ = writeln!(out, "{code}\n");
            let _ = writeln!(manifest, "{}\t{:#x}", e.name, e.rva);
            count += 1;
        }
        // Internal (non-exported) helper functions are referenced by name as
        // `fun_XXXXXXXX` in the emitted bodies but are not exports, so they were
        // never decompiled — leaving the .c with unresolved externals at link
        // time (board/checksums). Emit the transitive closure of referenced
        // helpers (NOT added to the manifest, so the harness neither exports nor
        // directly tests them; they exist only so the export bodies link).
        let known: std::collections::HashSet<u64> =
            engine.functions().iter().map(|f| f.rva).collect();
        loop {
            let mut pending: Vec<u64> = Vec::new();
            let bytes = out.as_bytes();
            let mut i = 0usize;
            while let Some(rel) = out[i..].find("fun_") {
                let start = i + rel + 4;
                let hex: String = bytes[start..]
                    .iter()
                    .take(8)
                    .take_while(|b| b.is_ascii_hexdigit())
                    .map(|&b| b as char)
                    .collect();
                i = start;
                if hex.len() == 8 {
                    if let Ok(rva) = u64::from_str_radix(&hex, 16) {
                        if known.contains(&rva) && !emitted.contains(&rva) {
                            pending.push(rva);
                        }
                    }
                }
            }
            if pending.is_empty() {
                break;
            }
            pending.sort_unstable();
            pending.dedup();
            for rva in pending {
                if !emitted.insert(rva) {
                    continue;
                }
                let code = engine.decompile(rva).unwrap_or_default();
                if code.trim().is_empty() {
                    continue;
                }
                let _ = writeln!(out, "/* ==== internal fun_{rva:08x} @ {rva:#x} ==== */");
                let _ = writeln!(out, "{code}\n");
            }
        }
        std::fs::write(format!("{outdir}\\{stem}.c"), &out).expect("write c");
        std::fs::write(format!("{outdir}\\{stem}.manifest"), &manifest).expect("write manifest");
        eprintln!("{stem}: decompiled {count} exported functions");
    }
}
