//! Overnight quality loop tooling: for each real-binary function, write a file
//! pairing its DISASSEMBLY with its DECOMPILED C so they can be read side by
//! side to find (and verify fixes for) real bugs. NOT a pass/fail test — it is a
//! dump generator. Output: _qa/pairs/fn_<rva>.txt (one per function).
//! Env: DS_REAL_BIN, DS_PAIRS_CAP (max funcs, default 400),
//!      DS_PAIRS_RVAS (comma list; if set, ONLY these).

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
fn dump_pairs() {
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
    /* Register requested RVAs as entries so undiscovered functions (reached only
     * via dispatch tables, like fun_0006dcd0) get bounds + a CFG and can be
     * decompiled — exactly what the GUI does when you open them by address. */
    let req_rvas: Vec<u64> = std::env::var("DS_PAIRS_RVAS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|x| u64::from_str_radix(x.trim().trim_start_matches("0x"), 16).ok())
                .collect()
        })
        .unwrap_or_default();
    for &rva in &req_rvas {
        engine.add_entry(rva);
    }
    engine.disassemble().expect("disasm");
    engine.build_cfg().expect("cfg");
    engine.resolve_symbols().expect("symbols");
    engine.build_xrefs().expect("xrefs");

    // Full linear listing once (rva-sorted), so each function slices its range.
    let total = engine.instruction_count();
    let all = engine.disasm_range(0, total);

    let funcs = engine.functions();
    let only: Option<Vec<u64>> = std::env::var("DS_PAIRS_RVAS").ok().map(|s| {
        s.split(',')
            .filter_map(|x| u64::from_str_radix(x.trim().trim_start_matches("0x"), 16).ok())
            .collect()
    });
    let cap: usize = std::env::var("DS_PAIRS_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);

    let dir = r"C:\Users\User\Downloads\sd\_qa\pairs";
    let _ = std::fs::create_dir_all(dir);
    let mut written = 0usize;
    let mut index = String::new();

    for f in funcs.iter() {
        if let Some(ref list) = only {
            if !list.contains(&f.rva) {
                continue;
            }
        } else if written >= cap {
            break;
        }
        let __t0 = std::time::Instant::now();
        let code = engine.decompile(f.rva).unwrap_or_default();
        if std::env::var("DS_TIMING").is_ok() {
            eprintln!("DSTIME {:#x} {}", f.rva, __t0.elapsed().as_millis());
        }
        if code.trim().is_empty() {
            continue;
        }
        let end = f.rva + f.size.max(1);
        let mut dis = String::new();
        for ins in all.iter().filter(|i| i.rva >= f.rva && i.rva < end) {
            dis.push_str(&format!("  {:#x}: {:<9} {}\n", ins.rva, ins.mnemonic, ins.operands));
        }
        let mut out = String::new();
        out.push_str(&format!(
            "=== fun_{:08x} @ {:#x} size={} blocks={} calls={} ===\n",
            f.rva, f.rva, f.size, f.block_count, f.call_count
        ));
        out.push_str("--- DISASM ---\n");
        out.push_str(&dis);
        out.push_str("--- DECOMPILED ---\n");
        out.push_str(&code);
        out.push('\n');
        let path = format!("{dir}\\fn_{:08x}.txt", f.rva);
        let _ = std::fs::write(&path, &out);
        index.push_str(&format!(
            "{:#x} size={} blocks={} calls={}\n",
            f.rva, f.size, f.block_count, f.call_count
        ));
        written += 1;
    }
    /* Requested RVAs that are NOT in the engine's auto-discovered function list
     * (reached only via dispatch tables / indirect calls, like fun_0006dcd0) are
     * still decompilable on-demand — the GUI does exactly this. Decompile each
     * uncovered requested RVA directly so it can be inspected/verified. */
    if let Some(ref list) = only {
        let have: std::collections::HashSet<u64> = funcs.iter().map(|f| f.rva).collect();
        for &rva in list.iter() {
            if have.contains(&rva) {
                continue;
            }
            let code = engine.decompile(rva).unwrap_or_default();
            if code.trim().is_empty() {
                continue;
            }
            let mut dis = String::new();
            for ins in all.iter().filter(|i| i.rva >= rva && i.rva < rva + 0x600) {
                dis.push_str(&format!("  {:#x}: {:<9} {}\n", ins.rva, ins.mnemonic, ins.operands));
            }
            let mut out = String::new();
            out.push_str(&format!("=== fun_{:08x} @ {:#x} (on-demand, undiscovered) ===\n", rva, rva));
            out.push_str("--- DISASM ---\n");
            out.push_str(&dis);
            out.push_str("--- DECOMPILED ---\n");
            out.push_str(&code);
            out.push('\n');
            let _ = std::fs::write(format!("{dir}\\fn_{:08x}.txt", rva), &out);
            written += 1;
        }
    }
    let _ = std::fs::write(format!("{dir}\\_index.txt"), &index);
    eprintln!("dump_pairs: wrote {written} function pair-files to {dir}");
}
