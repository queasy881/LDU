//! Interactive retyping (IDA-1): setting a variable's type changes the NEXT
//! decompile of THAT function, and nothing else.
//!
//! The second assertion is the one that matters for usability. A retype must not
//! re-run analysis or invalidate other functions -- IDA re-decompiles the one
//! function you are looking at. This test pins that: it records every other
//! function's output before the retype and requires it byte-identical after, and
//! it times the retype+re-decompile against the initial full decompile.
//!
//! Env: DS_REAL_BIN (else a corpus DLL).

use binparser::{Arch as PArch, BinaryMeta};
use bridge::{Arch as BArch, Engine};

mod common;

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
fn retype_is_local_and_effective() {
    let bin = match common::real_bin() {
        Some(b) => b,
        None => {
            eprintln!("{}", common::NO_REAL_BIN);
            return;
        }
    };
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

    // A sample of functions; the first that declares a plain `a1` is the target.
    let funcs: Vec<u64> = engine.functions().iter().map(|f| f.rva).take(120).collect();
    let t_all = std::time::Instant::now();
    let before: Vec<(u64, String)> = funcs
        .iter()
        .map(|&r| (r, common::on_worker_stack(|| engine.decompile(r).unwrap_or_default())))
        .collect();
    let full_decompile = t_all.elapsed();

    let target = before
        .iter()
        .find(|(_, c)| c.contains("a1") && !c.trim().is_empty())
        .map(|(r, _)| *r);
    let target = match target {
        Some(t) => t,
        None => {
            eprintln!("[skip] no sampled function declares a1");
            return;
        }
    };

    // ---- the retype -------------------------------------------------------
    let t_retype = std::time::Instant::now();
    engine.set_var_type(target, "a1", "struct MyThing*");
    let after_target = common::on_worker_stack(|| engine.decompile(target).unwrap_or_default());
    let retype_cost = t_retype.elapsed();

    let before_target = &before.iter().find(|(r, _)| *r == target).unwrap().1;
    assert!(
        after_target.contains("struct MyThing*"),
        "retype had no effect on {target:#x}; output was:\n{}",
        &after_target[..after_target.len().min(600)]
    );
    assert_ne!(before_target, &after_target, "retype produced identical output");

    // ---- and it touched NOTHING else --------------------------------------
    let mut changed = 0usize;
    for (r, was) in &before {
        if *r == target {
            continue;
        }
        let now = common::on_worker_stack(|| engine.decompile(*r).unwrap_or_default());
        if &now != was {
            changed += 1;
            if changed <= 3 {
                eprintln!("UNEXPECTED change in {r:#x}");
            }
        }
    }
    assert_eq!(changed, 0, "{changed} other functions changed after a retype");

    // Re-decompiling ONE function must be far cheaper than the whole set. This is
    // the usability property: a rename/retype is not a reanalysis.
    eprintln!(
        "RETYPE: full decompile of {} fns = {:?}; one retype+re-decompile = {:?}",
        before.len(),
        full_decompile,
        retype_cost
    );
    assert!(
        retype_cost * 4 < full_decompile,
        "retype cost {retype_cost:?} is not clearly cheaper than a full pass {full_decompile:?}"
    );

    // Clearing restores the recovered type.
    engine.set_var_type(target, "a1", "");
    let restored = common::on_worker_stack(|| engine.decompile(target).unwrap_or_default());
    assert_eq!(
        &restored, before_target,
        "clearing the override did not restore the original output"
    );
    eprintln!("RETYPE: ok (effective, local, reversible)");
}
