//! Engine verification harness. Runs the full pipeline on the controlled
//! _qa/testdll.dll and dumps every analysis dimension to _qa/engine_dump.txt so
//! it can be diffed against ground truth (llvm-objdump / dumpbin).
//!
//! Run: cargo test -p disasmstudio --test verify_engine -- --nocapture

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

const DLL: &str = r"C:\Users\User\Downloads\sd\_qa\testdll.dll";

#[test]
fn dump_engine() {
    if !std::path::Path::new(DLL).exists() {
        eprintln!("[skip] {DLL} not built");
        return;
    }
    let bytes = std::fs::read(DLL).expect("read dll");
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
    for &cb in &parsed.tls_callbacks {
        engine.add_entry(cb);
    }
    for imp in &parsed.imports {
        engine.add_import(imp.rva, &imp.name);
    }
    engine.disassemble().expect("disasm");
    engine.build_cfg().expect("cfg");
    engine.resolve_symbols().expect("symbols");
    engine.build_xrefs().expect("xrefs");

    let mut o = String::new();
    let _ = writeln!(
        o,
        "BASE {:#x} ENTRY {:#x} ISDLL {} ARCH {:?}",
        parsed.base, parsed.entry, parsed.is_dll, parsed.arch
    );
    for s in engine.segments() {
        let p = format!(
            "{}{}{}",
            if s.flags & 1 != 0 { "R" } else { "-" },
            if s.flags & 2 != 0 { "W" } else { "-" },
            if s.flags & 4 != 0 { "X" } else { "-" }
        );
        let _ = writeln!(o, "SEG {} rva={:#x} size={:#x} {}", s.name, s.rva, s.size, p);
    }
    let mut exps = parsed.exports.clone();
    exps.sort_by_key(|e| e.rva);
    for e in &exps {
        let _ = writeln!(o, "EXP {:#x} {}", e.rva, e.name);
    }
    let mut imps = parsed.imports.clone();
    imps.sort_by(|a, b| a.name.cmp(&b.name));
    for i in &imps {
        let _ = writeln!(o, "IMP {:#x} {}", i.rva, i.name);
    }
    for f in engine.functions() {
        let _ = writeln!(
            o,
            "FUNC {:#x} {} size={} blocks={} calls={}",
            f.rva, f.name, f.size, f.block_count, f.call_count
        );
    }

    // Full instruction listing, in index (address) order.
    let n = engine.instruction_count();
    let mut idx = 0usize;
    while idx < n {
        let take = 4096.min(n - idx);
        let batch = engine.disasm_range(idx, take);
        if batch.is_empty() {
            break;
        }
        for insn in &batch {
            let _ = writeln!(o, "INSN {:#x}\t{}\t{}", insn.rva, insn.mnemonic, insn.operands);
        }
        idx += batch.len();
        if batch.len() < take {
            break;
        }
    }

    // ---- strings (mirrors session::scan_strings: skip executable segments) ----
    let printable = |b: u8| (0x20..=0x7e).contains(&b) || b == b'\t';
    let mut strs: Vec<(u64, u8, String)> = Vec::new();
    for s in engine.segments() {
        if s.flags & 4 != 0 || s.size == 0 {
            continue; // skip executable / empty
        }
        let bytes = engine.read_bytes(s.rva, s.size as usize);
        let n = bytes.len();
        let mut i = 0;
        while i < n {
            if printable(bytes[i]) {
                let start = i;
                let mut j = i;
                while j < n && printable(bytes[j]) {
                    j += 1;
                }
                if j - start >= 5 && (j >= n || bytes[j] == 0) {
                    let take = (j - start).min(240);
                    let v: String = bytes[start..start + take].iter().map(|&c| c as char).collect();
                    strs.push((s.rva + start as u64, 0, v));
                }
                i = j;
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i + 1 < n {
            if printable(bytes[i]) && bytes[i + 1] == 0 {
                let start = i;
                let mut v = String::new();
                let mut j = i;
                while j + 1 < n && printable(bytes[j]) && bytes[j + 1] == 0 && v.len() < 240 {
                    v.push(bytes[j] as char);
                    j += 2;
                }
                if v.len() >= 5 && (j >= n || bytes[j] == 0) {
                    strs.push((s.rva + start as u64, 1, v));
                }
                i = j.max(i + 2);
            } else {
                i += 1;
            }
        }
    }
    strs.sort_by_key(|(r, _, _)| *r);
    for (rva, k, v) in &strs {
        let _ = writeln!(o, "STR {rva:#x} {k} {v}");
    }
    eprintln!("strings: {}", strs.len());

    std::fs::write(r"C:\Users\User\Downloads\sd\_qa\engine_dump.txt", &o).expect("write dump");
    eprintln!(
        "engine dump: {} insns, {} funcs, {} exports, {} imports",
        n,
        engine.functions().len(),
        parsed.exports.len(),
        parsed.imports.len()
    );

    // Sanity assertions on the controlled DLL.
    let funcs = engine.functions();
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    for want in ["add", "sub", "fib", "sum_array", "classify", "do_api", "grand_total", "DllEntryPoint"] {
        assert!(names.contains(&want), "missing recovered export/function: {want}");
    }
    assert!(n > 100, "too few instructions: {n}");

    // ---- string-quality assertions ----
    let svals: Vec<&str> = strs.iter().map(|(_, _, v)| v.as_str()).collect();
    assert!(
        svals.iter().any(|s| s.contains("DisasmStudio test string")),
        "missing the known ASCII string"
    );
    assert!(
        svals.iter().any(|s| s.contains("wide unicode marker")),
        "missing the known UTF-16 string"
    );
    // No string may originate inside an executable (.text) segment — those are
    // code-byte false positives.
    if let Some(t) = engine.segments().into_iter().find(|s| s.flags & 4 != 0) {
        let (lo, hi) = (t.rva, t.rva + t.size);
        assert!(
            !strs.iter().any(|(r, _, _)| *r >= lo && *r < hi),
            "strings leaked from executable segment {} [{:#x},{:#x})",
            t.name, lo, hi
        );
    }

    // The known string is passed to OutputDebugStringA, so code must reference
    // it — this is what makes click-a-string-go-to-its-use work.
    if let Some((srva, _, _)) = strs.iter().find(|(_, _, v)| v.contains("DisasmStudio test string")) {
        let xr = engine.xrefs_to(*srva);
        eprintln!("xrefs to known string @ {srva:#x}: {}", xr.len());
        assert!(!xr.is_empty(), "known string has no xref — click-to-use would fail");
    }
}
