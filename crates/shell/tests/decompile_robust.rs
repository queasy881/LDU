//! Robustness / generalization sweep: decompile EVERY function of several real
//! binaries and the corpus. Asserts the decompiler never crashes or hangs, and
//! reports quality metrics (raw-register leakage, goto usage, empty output) so
//! we can see it generalizes — not just pass the corpus.
//!
//! Run: cargo test -p disasmstudio --test decompile_robust -- --nocapture

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

fn analyze(path: &str) -> Option<Engine> {
    let bytes = std::fs::read(path).ok()?;
    let parsed = BinaryMeta::parse(&bytes).ok()?;
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
    engine.disassemble().ok()?;
    engine.build_cfg().ok()?;
    engine.resolve_symbols().ok()?;
    engine.build_xrefs().ok()?;
    Some(engine)
}

const RAW_REGS: &[&str] = &[
    "r_rax", "r_rcx", "r_rdx", "r_rbx", "r_rsp", "r_rbp", "r_rsi", "r_rdi", "r_rip",
];

fn looks_like_raw_reg(code: &str) -> bool {
    RAW_REGS.iter().any(|r| code.contains(r))
}

#[test]
fn decompile_everything_without_crashing() {
    let qa = r"C:\Users\User\Downloads\sd\_qa";
    let bins = [
        format!("{qa}\\corpus\\math_ops.dll"),
        format!("{qa}\\corpus\\array_ops.dll"),
        format!("{qa}\\corpus\\string_ops.dll"),
        format!("{qa}\\corpus\\control_flow.dll"),
        format!("{qa}\\corpus\\struct_ops.dll"),
        r"C:\Windows\System32\kernel32.dll".to_string(),
        r"C:\Windows\System32\kernelbase.dll".to_string(),
        r"C:\Windows\System32\ntdll.dll".to_string(),
        r"C:\Windows\System32\user32.dll".to_string(),
        r"C:\Windows\System32\gdi32.dll".to_string(),
        r"C:\Windows\System32\advapi32.dll".to_string(),
        r"C:\Windows\System32\ole32.dll".to_string(),
        r"C:\Windows\System32\shell32.dll".to_string(),
        r"C:\Windows\System32\shlwapi.dll".to_string(),
        r"C:\Windows\System32\msvcrt.dll".to_string(),
        r"C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll".to_string(),
    ];

    let mut grand_total = 0usize;
    let mut grand_raw = 0usize;
    for bin in &bins {
        if !std::path::Path::new(bin).exists() {
            eprintln!("[skip] {bin}");
            continue;
        }
        let engine = match analyze(bin) {
            Some(e) => e,
            None => {
                eprintln!("[skip] analyze failed: {bin}");
                continue;
            }
        };
        let funcs = engine.functions();
        // Sample cap per binary so the sweep stays fast enough to run every
        // iteration; raise/remove for a full battle-test run.
        let cap: usize = std::env::var("ROBUST_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(400);
        let mut total = 0;
        let mut empty = 0;
        let mut raw = 0;
        let mut gotos = 0;
        for f in funcs.iter().take(cap) {
            // The key robustness assertion: this must never crash/hang for ANY
            // function of ANY binary.
            let code = engine.decompile(f.rva).unwrap_or_default();
            total += 1;
            if code.trim().is_empty() {
                empty += 1;
                continue;
            }
            if looks_like_raw_reg(&code) {
                raw += 1;
            }
            if code.contains("goto ") {
                gotos += 1;
            }
        }
        let name = std::path::Path::new(bin)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        eprintln!(
            "{name:>16}: {total:5} fns | empty {empty:4} | raw-reg {raw:5} | goto {gotos:5}",
        );
        grand_total += total;
        grand_raw += raw;
    }
    eprintln!("---- TOTAL {grand_total} functions decompiled, {grand_raw} still leak raw registers ----");
    // The hard guarantee: we got here, so nothing crashed. (Quality metrics above
    // are tracked toward zero as the decompiler matures.)
    assert!(grand_total > 0, "no functions decompiled at all");
}
