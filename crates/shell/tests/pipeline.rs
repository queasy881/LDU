//! End-to-end backend pipeline test on a real on-disk binary.
//!
//! Mirrors the analysis worker in `app.rs` (parse -> build_image -> engine ->
//! disassemble -> cfg -> resolve_symbols -> xrefs) and asserts the engine
//! produces real output: many instructions, recovered functions, and genuine
//! names (exports + a `DllMain` entry for a DLL) rather than only `fun_xxxx`.
//!
//! Run with: `cargo test -p disasmstudio --test pipeline -- --nocapture`

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

/// Pick the first existing candidate binary, or None to skip.
fn sample_binary() -> Option<String> {
    let candidates = [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\user32.dll",
        r"C:\Windows\System32\ntdll.dll",
    ];
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

#[test]
fn full_pipeline_recovers_real_names() {
    let path = match sample_binary() {
        Some(p) => p,
        None => {
            eprintln!("[skip] no sample system DLL found; skipping pipeline test");
            return;
        }
    };
    eprintln!("=== analyzing {path} ===");

    let bytes = std::fs::read(&path).expect("read binary");
    let parsed = BinaryMeta::parse(&bytes).expect("parse binary");

    eprintln!(
        "format={:?} arch={:?} base=0x{:x} entry=0x{:x} is_dll={} segments={} exports={} imports={} tls={}",
        parsed.format,
        parsed.arch,
        parsed.base,
        parsed.entry,
        parsed.is_dll,
        parsed.segments.len(),
        parsed.exports.len(),
        parsed.imports.len(),
        parsed.tls_callbacks.len(),
    );

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
    for &cb in &parsed.tls_callbacks {
        engine.add_entry(cb);
    }
    for imp in &parsed.imports {
        engine.add_import(imp.rva, &imp.name);
    }

    engine.disassemble().expect("disassemble");
    engine.build_cfg().expect("build_cfg");
    engine.resolve_symbols().expect("resolve_symbols");
    engine.build_xrefs().expect("build_xrefs");

    let meta = engine.meta();
    let funcs = engine.functions();
    let insn_count = engine.instruction_count();
    eprintln!(
        "engine: functions={} instructions={} segments={}",
        meta.function_count, insn_count, meta.segment_count
    );

    // --- core sanity --------------------------------------------------------
    assert!(insn_count > 1000, "expected many instructions, got {insn_count}");
    assert!(!funcs.is_empty(), "expected recovered functions");

    // --- name recovery quality ---------------------------------------------
    let total = funcs.len();
    let fallback = funcs.iter().filter(|f| f.name.starts_with("fun_")).count();
    let named = total - fallback;
    let thunks = funcs.iter().filter(|f| f.name.starts_with("j_")).count();
    let has_dllmain = funcs.iter().any(|f| f.name == "DllMain" || f.name == "start");
    eprintln!(
        "names: {named}/{total} resolved ({fallback} fallback fun_, {thunks} import thunks j_)",
    );

    // Print a sample of recovered (non-fallback) names.
    eprintln!("-- sample recovered functions --");
    for f in funcs.iter().filter(|f| !f.name.starts_with("fun_")).take(15) {
        eprintln!(
            "  0x{:08x}  {:<40} size={} blocks={} calls={}",
            f.rva, f.name, f.size, f.block_count, f.call_count
        );
    }

    assert!(
        named > 0,
        "symbol resolution produced zero real names (all fun_)"
    );
    assert!(
        has_dllmain,
        "entry point was not named DllMain/start"
    );

    // --- real disassembly ---------------------------------------------------
    // Find an instruction index inside the first executable segment's function.
    let first_fn = funcs
        .iter()
        .min_by_key(|f| f.rva)
        .expect("at least one function");
    if let Some(start) = engine.index_for_rva(first_fn.rva) {
        let insns = engine.disasm_range(start, 12);
        eprintln!("-- disassembly @ {} (0x{:08x}) --", first_fn.name, first_fn.rva);
        for ins in &insns {
            let bytes: String = ins
                .bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let target = ins
                .ref_target
                .map(|t| format!("  -> 0x{t:x}"))
                .unwrap_or_default();
            eprintln!(
                "  0x{:08x}  {:<24}  {} {}{}",
                ins.rva, bytes, ins.mnemonic, ins.operands, target
            );
        }
        assert!(!insns.is_empty(), "disasm_range returned no instructions");
        assert!(
            insns.iter().any(|i| !i.mnemonic.is_empty() && i.mnemonic != "db"),
            "all decoded instructions were raw db bytes"
        );
    }

    // --- xrefs --------------------------------------------------------------
    // Find a function that is called by something and check the xref index.
    let mut xref_demo = None;
    for f in funcs.iter() {
        let xs = engine.xrefs_to(f.rva);
        if !xs.is_empty() {
            xref_demo = Some((f.clone(), xs));
            break;
        }
    }
    if let Some((f, xs)) = xref_demo {
        eprintln!("-- xrefs to {} (0x{:08x}): {} --", f.name, f.rva, xs.len());
        for x in xs.iter().take(6) {
            let kind = match x.kind {
                1 => "CALL",
                2 => "JMP",
                3 => "DATA",
                _ => "?",
            };
            eprintln!("  from 0x{:08x}  {}", x.from_rva, kind);
        }
    }

    eprintln!("=== pipeline OK ===");
}
