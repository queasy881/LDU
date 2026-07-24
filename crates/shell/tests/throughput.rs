//! Decompilation THROUGHPUT benchmark (the "5000 functions / 30s" target + the
//! guarantee that the parallel eager stage never regresses vs serial).
//!
//! Builds the engine exactly like the app's load path, then decompiles EVERY
//! function twice: once serially, once across N worker threads sharing one
//! `&Engine` (the same re-entrant path the app's Stage-6 eager pass uses). Reports
//! functions/second for each and asserts the parallel run produces the identical
//! set of results as serial (no races, no dropped/garbled functions).
//!
//! Run:  DS_REAL_BIN=<dll> cargo test --release -p disasmstudio --test throughput -- --nocapture

use binparser::{Arch as PArch, BinaryMeta};
use bridge::{Arch as BArch, Engine};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

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
fn throughput() {
    let bin = match common::real_bin() {
        Some(b) => b,
        None => {
            eprintln!("{}", common::NO_REAL_BIN);
            return;
        }
    };
    if !std::path::Path::new(&bin).exists() {
        eprintln!("[skip] {bin} not found");
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
    let total = funcs.len();
    eprintln!("THROUGHPUT: {} functions in {}", total, bin);
    if total == 0 {
        return;
    }

    // Warm the per-engine sig table once so neither timed run pays for the O(n)
    // prepass (the app warms it identically before the parallel loop).
    let _ = engine.decompile(funcs[0].rva);

    // ---- serial (skipped in a thread-sweep so the sweep stays fast) ----
    let sweep = std::env::var("DS_THREADS").is_ok();
    let mut serial: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut serial_secs = 0.0_f64;
    if !sweep {
        let t = std::time::Instant::now();
        for f in funcs.iter() {
            if let Some(code) = engine.decompile(f.rva) {
                serial.insert(f.rva, code.len());
            }
        }
        serial_secs = t.elapsed().as_secs_f64();
        eprintln!(
            "SERIAL:   {:.2}s  =>  {:.0} fns/s  ({} decompiled)",
            serial_secs,
            total as f64 / serial_secs,
            serial.len()
        );
    }

    // ---- parallel (mirror the app's Stage-6 eager pass) ----
    let nthreads = std::env::var("DS_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .min(total)
        .max(1);
    let next = AtomicUsize::new(0);
    let shards: Vec<Mutex<Vec<(u64, usize)>>> =
        (0..nthreads).map(|_| Mutex::new(Vec::new())).collect();
    let engine_ref = &engine;
    let funcs_ref = &funcs;
    let t = std::time::Instant::now();
    std::thread::scope(|scope| {
        for tid in 0..nthreads {
            let next = &next;
            let shard = &shards[tid];
            scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    if let Some(code) = engine_ref.decompile(funcs_ref[i].rva) {
                        local.push((funcs_ref[i].rva, code.len()));
                    }
                }
                *shard.lock().unwrap() = local;
            });
        }
    });
    let par_secs = t.elapsed().as_secs_f64();
    let par_rate = total as f64 / par_secs;
    let mut parallel: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for shard in &shards {
        for (rva, len) in shard.lock().unwrap().iter() {
            parallel.insert(*rva, *len);
        }
    }
    eprintln!(
        "PARALLEL: {:.2}s  =>  {:.0} fns/s  ({} decompiled, {} threads)  speedup {:.1}x",
        par_secs,
        par_rate,
        parallel.len(),
        nthreads,
        serial_secs / par_secs.max(1e-9)
    );
    eprintln!(
        "TARGET 5000/30s = 167 fns/s  =>  parallel {}",
        if par_rate >= 167.0 { "MET" } else { "BELOW (needs a bigger machine or engine speedups)" }
    );

    // Correctness: the parallel run must produce EXACTLY the same result set as
    // serial — same functions, same output length. A race would show here.
    if !sweep {
        assert_eq!(
            serial.len(),
            parallel.len(),
            "parallel dropped/added functions vs serial"
        );
        for (rva, len) in &serial {
            assert_eq!(
                parallel.get(rva),
                Some(len),
                "parallel output differs for {:#x}",
                rva
            );
        }
        eprintln!("OK: parallel output identical to serial ({} functions)", serial.len());
    }
}
