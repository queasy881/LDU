//! Quality scanner over real-binary functions (no source to diff, so we score
//! the failure SIGNATURES we know about). Drives toward zero across a sample.
//! Run: cargo test --release -p disasmstudio --test decompile_real -- --nocapture
//! Env: DS_REAL_BIN, DS_REAL_CAP (sample size), DS_REAL_RVAS (dump these).

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

struct Score {
    null_base: usize,  // (char*)(0)        — lost base register
    null_call: usize,  // (*)())(0)         — lost function pointer
    const_cond: usize, // if(0==0)/if(1)... — lost compare operands
    bailout: usize,    // structurer bailout / DBG markers
    goto: usize,
}

fn score(code: &str) -> Score {
    let cc = code.matches("if (0 == 0)").count()
        + code.matches("if (0 != 0)").count()
        + code.matches("if (1)").count()
        + code.matches("if (!1)").count()
        + code.matches("if (0)").count();
    Score {
        null_base: code.matches("(char*)(0)").count() + code.matches("(char*)(0 ").count(),
        null_call: code.matches("(*)())(0)").count() + code.matches("())(0))").count(),
        const_cond: cc,
        bailout: code.matches("structurer bailout").count() + code.matches("/* decompilation").count(),
        goto: code.matches("goto ").count(),
    }
}

#[test]
fn quality_scan_real() {
    let bin = std::env::var("DS_REAL_BIN").unwrap_or_else(|_| {
        r"C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll".into()
    });
    if !std::path::Path::new(&bin).exists() {
        eprintln!("[skip] {bin}");
        return;
    }
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

    let funcs = engine.functions();
    let cap: usize = std::env::var("DS_REAL_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(120);
    let (mut nb, mut nc, mut cc, mut bo, mut total) = (0, 0, 0, 0, 0usize);
    let mut clean = 0usize;
    // (issue_count, rva) for worst offenders
    let mut worst: Vec<(usize, u64)> = Vec::new();
    for f in funcs.iter().take(cap) {
        let code = engine.decompile(f.rva).unwrap_or_default();
        if code.trim().is_empty() {
            continue;
        }
        total += 1;
        let s = score(&code);
        nb += s.null_base; nc += s.null_call; cc += s.const_cond; bo += s.bailout;
        let issues = s.null_base + s.null_call + s.const_cond + s.bailout;
        if issues == 0 { clean += 1; }
        worst.push((issues, f.rva));
        let _ = s.goto;
    }
    worst.sort_by(|a, b| b.0.cmp(&a.0));
    eprintln!("==== QUALITY over {total} fns ====");
    eprintln!("  clean (0 issues): {clean}  ({}%)", clean * 100 / total.max(1));
    eprintln!("  null-base:   {nb}");
    eprintln!("  null-call:   {nc}");
    eprintln!("  const-cond:  {cc}");
    eprintln!("  bailout:     {bo}");
    eprintln!("  worst RVAs:  {:?}", worst.iter().take(8).map(|(n, r)| format!("{r:#x}={n}")).collect::<Vec<_>>());

    // Dump a representative spread: the worst offenders AND every Nth function,
    // so we read real samples (not only the pathological ones).
    let mut out = String::new();
    let mut dumped: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for (_, rva) in worst.iter().take(8) {
        if dumped.insert(*rva) {
            out.push_str(&format!("\n/* ===== WORST @ {rva:#x} ===== */\n{}\n", engine.decompile(*rva).unwrap_or_default()));
        }
    }
    let step = (total / 12).max(1);
    for (i, f) in funcs.iter().take(cap).enumerate() {
        if i % step == 0 && dumped.insert(f.rva) {
            out.push_str(&format!("\n/* ===== SAMPLE @ {:#x} ===== */\n{}\n", f.rva, engine.decompile(f.rva).unwrap_or_default()));
        }
    }
    if let Ok(rvas) = std::env::var("DS_REAL_RVAS") {
        for r in rvas.split(',').filter_map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()) {
            out.push_str(&format!("\n/* ===== (req) @ {r:#x} ===== */\n{}\n", engine.decompile(r).unwrap_or_default()));
        }
    }
    let _ = std::fs::write(r"C:\Users\User\Downloads\sd\_qa\real_dump.c", &out);
    eprintln!("  (worst 6 dumped to _qa/real_dump.c)");
}
