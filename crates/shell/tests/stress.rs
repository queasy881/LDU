//! FAST stress dumper for LARGE DLLs. Unlike dump_pairs (which builds a full linear disasm
//! listing and re-filters it O(n^2) per function, then writes a file per function), this only
//! DECOMPILES and tallies metrics in memory, writing at most one combined .c for a compile
//! check. That makes a multi-MB DLL tractable in seconds-to-minutes instead of tens of minutes.
//!
//! Env:
//!   DS_REAL_BIN     the DLL to stress (REQUIRED; no NullWare default here).
//!   DS_STRESS_CAP   max functions (default 4000).
//!   DS_STRESS_OUT   if set, write a combined <dir>/stress_all.c + slow-function list there.
//!   DS_STRESS_TOPSLOW  print the N slowest functions (default 15).
//!
//! Prints a summary: totals, in_<REG> phantom leaks, goto count, empty/oversized, timing.

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

fn count_occ(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

/// count `goto <label>;` (semicolon-anchored, so the confidence-header text does not inflate it)
fn count_gotos(s: &str) -> usize {
    let mut n = 0;
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(p) = s[i..].find("goto ") {
        let start = i + p + 5;
        let mut e = start;
        while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'_') {
            e += 1;
        }
        if e > start && e < b.len() && b[e] == b';' {
            n += 1;
        }
        i = start;
    }
    n
}

/// count distinct `in_<REG>` phantom identifiers (any letters/digits after in_ up to a non-ident)
fn count_in_reg(s: &str) -> usize {
    let mut n = 0;
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(p) = s[i..].find("in_") {
        let at = i + p;
        // must be a token start (prev char non-ident)
        let prev_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        let c = b.get(at + 3).copied().unwrap_or(0);
        if prev_ok && c.is_ascii_uppercase() {
            n += 1;
        }
        i = at + 3;
    }
    n
}

mod common;

#[test]
fn stress() {
    let bin = std::env::var("DS_REAL_BIN").expect("DS_REAL_BIN required (no default)");
    if !std::path::Path::new(&bin).exists() {
        eprintln!("[skip] {bin} not found");
        return;
    }
    let cap: usize = std::env::var("DS_STRESS_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(4000);
    let topslow: usize = std::env::var("DS_STRESS_TOPSLOW").ok().and_then(|v| v.parse().ok()).unwrap_or(15);

    let t_load = std::time::Instant::now();
    let bytes = std::fs::read(&bin).expect("read");
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
    let load_ms = t_load.elapsed().as_millis();

    let funcs = engine.functions();
    let total_funcs = funcs.len();

    let mut done = 0usize;
    let mut empty = 0usize;
    let mut gotos = 0usize;
    let mut goto_fns = 0usize;
    let mut in_reg = 0usize;
    let mut in_reg_fns = 0usize;
    let mut total_chars = 0usize;
    let mut biglines = 0usize; // lines over 400 chars
    let mut slow: Vec<(u64, u128, u32)> = Vec::new(); // (rva, ms, size)
    let mut combined = String::new();
    let out_dir = std::env::var("DS_STRESS_OUT").ok();

    let t_all = std::time::Instant::now();
    // Production stack: see common::on_worker_stack.
    common::on_worker_stack(|| {
    for f in funcs.iter().take(cap) {
        if std::env::var("DS_TRACE_FN").is_ok() {
            eprintln!("[FN] {:#x} size={}", f.rva, f.size);
            use std::io::Write as _;
            let _ = std::io::stderr().flush();
        }
        let t0 = std::time::Instant::now();
        let code = engine.decompile(f.rva).unwrap_or_default();
        let ms = t0.elapsed().as_millis();
        if slow.len() < topslow * 4 {
            slow.push((f.rva, ms, f.size as u32));
        } else if let Some((_, m, _)) = slow.iter().enumerate().min_by_key(|(_, (_, m, _))| *m).map(|(_, x)| x) {
            if ms > *m {
                let idx = slow.iter().enumerate().min_by_key(|(_, (_, m, _))| *m).map(|(i, _)| i).unwrap();
                slow[idx] = (f.rva, ms, f.size as u32);
            }
        }
        done += 1;
        if code.trim().is_empty() {
            empty += 1;
            continue;
        }
        let g = count_gotos(&code);
        let ir = count_in_reg(&code);
        gotos += g;
        if g > 0 { goto_fns += 1; }
        in_reg += ir;
        if ir > 0 { in_reg_fns += 1; }
        total_chars += code.len();
        for line in code.lines() {
            if line.len() > 400 { biglines += 1; }
        }
        if out_dir.is_some() {
            combined.push_str(&format!("/* ==== fun_{:08x} size={} ==== */\n", f.rva, f.size));
            combined.push_str(&code);
            combined.push('\n');
        }
    }
    });
    let all_ms = t_all.elapsed().as_millis();

    if let Some(dir) = &out_dir {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(format!("{dir}/stress_all.c"), &combined);
    }

    slow.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!("\n================ STRESS: {bin}");
    eprintln!("  functions discovered : {total_funcs}");
    eprintln!("  decompiled           : {done}  (empty {empty})");
    eprintln!("  IN_REG phantom leaks : {in_reg}  across {in_reg_fns} fns   <- MUST be low/0");
    eprintln!("  gotos                : {gotos}  across {goto_fns} fns");
    eprintln!("  total chars          : {total_chars}");
    eprintln!("  lines over 400 chars : {biglines}");
    eprintln!("  load+cfg time        : {load_ms} ms");
    eprintln!("  decompile time       : {all_ms} ms  ({} fns/s)",
              if all_ms > 0 { (done as u128 * 1000 / all_ms) as u64 } else { 0 });
    eprintln!("  --- {topslow} slowest functions (rva, ms, size) ---");
    for (rva, ms, sz) in slow.iter().take(topslow) {
        eprintln!("    {rva:#010x}  {ms:>5} ms  size={sz}");
    }
}
