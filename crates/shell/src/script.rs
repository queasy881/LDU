//! Headless scripting surface (IDA-5).
//!
//! Everything the analysis can do was reachable only by clicking in the GUI, so
//! the things people actually automate in IDA — bulk renaming, sweeping every
//! function for a pattern, applying a recovered struct everywhere, exporting
//! pseudocode — had no path at all.
//!
//! Rather than embed an interpreter (and its build dependency, and its FFI
//! surface), this exposes the engine as a line-oriented JSON command stream, so a
//! script in ANY language drives it over a pipe:
//!
//! ```text
//! disasmstudio --script target.dll commands.jsonl      # or - for stdin
//! ```
//!
//! One JSON object per line in, one JSON object per line out, in order. A command
//! that fails answers `{"ok":false,"error":...}` and the stream CONTINUES, so one
//! bad rva in a 10k-function sweep does not discard the run.
//!
//! Commands:
//!   {"cmd":"meta"}                                  -> arch/base/entry/counts
//!   {"cmd":"functions"[,"limit":N][,"offset":N]}    -> [{rva,name,size,blocks,calls}]
//!   {"cmd":"decompile","rva":"0x1000"}              -> {code}
//!   {"cmd":"disasm","rva":"0x1000"[,"count":N]}     -> [{rva,mnemonic,operands}]
//!   {"cmd":"strings"[,"limit":N]}                   -> [{rva,text,kind}]
//!   {"cmd":"xrefs","rva":"0x1000"}                  -> [{from,to,kind}]
//!   {"cmd":"rename","rva":"0x1000","name":"parse"}  -> {ok}
//!   {"cmd":"comment","rva":"0x1000","text":"..."}   -> {ok}
//!   {"cmd":"set_var_type","rva":..,"var":"a1","type":"struct Foo*"} -> {ok}
//!   {"cmd":"save_annotations","path":"x.json"}      -> {ok}
//!   {"cmd":"load_annotations","path":"x.json"}      -> {ok}
//!
//! `rva` accepts "0x1000", "1000" (hex) or a JSON number, because scripts emit all
//! three and rejecting two of them is just friction.

use std::io::{BufRead, Write};

use binparser::{Arch as PArch, BinaryMeta};
use bridge::{Arch as BArch, Engine};
use serde_json::{json, Value};

fn map_arch(a: PArch) -> BArch {
    match a {
        PArch::X86 => BArch::X86,
        PArch::X64 => BArch::X64,
        PArch::Arm => BArch::Arm,
        PArch::Arm64 => BArch::Arm64,
        PArch::Unknown => BArch::X64,
    }
}

/// Accept a number, "0x1000", or a bare hex string.
fn parse_rva(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => {
            let t = s.trim();
            let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
            u64::from_str_radix(t, 16).ok()
        }
        _ => None,
    }
}

fn build_engine(path: &str) -> Result<Engine, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let parsed = BinaryMeta::parse(&bytes).map_err(|e| format!("parse: {e}"))?;
    let image = parsed.build_image(&bytes);
    let mut engine = Engine::new(image, parsed.base, map_arch(parsed.arch));
    engine.set_is_dll(parsed.is_dll);
    engine.set_entry_rva(parsed.entry);
    if let Some(dir) = std::path::Path::new(path).parent() {
        engine.set_pdb_dir(&dir.to_string_lossy());
    }
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
    engine.disassemble().map_err(|e| format!("disassemble: {e}"))?;
    engine.build_cfg().map_err(|e| format!("build_cfg: {e}"))?;
    engine.resolve_symbols().map_err(|e| format!("resolve_symbols: {e}"))?;
    engine.build_xrefs().map_err(|e| format!("build_xrefs: {e}"))?;
    Ok(engine)
}

fn run_cmd(engine: &mut Engine, msg: &Value) -> Result<Value, String> {
    let cmd = msg.get("cmd").and_then(Value::as_str).unwrap_or("");
    let rva = || parse_rva(msg.get("rva"));
    let limit = msg
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX) as usize;
    let offset = msg.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;

    match cmd {
        "meta" => {
            let m = engine.meta();
            Ok(json!({
                "arch": format!("{:?}", m.arch), "base": m.base, "entry": m.entry,
                "image_size": m.image_size, "segments": m.segment_count,
                "functions": m.function_count, "instructions": m.instruction_count,
            }))
        }
        "functions" => {
            let out: Vec<Value> = engine
                .functions()
                .iter()
                .skip(offset)
                .take(limit)
                .map(|f| {
                    json!({ "rva": f.rva, "name": f.name, "size": f.size,
                            "blocks": f.block_count, "calls": f.call_count })
                })
                .collect();
            Ok(Value::Array(out))
        }
        "decompile" => {
            let r = rva().ok_or("decompile: missing/!rva")?;
            match engine.decompile(r) {
                Some(c) if !c.trim().is_empty() => Ok(json!({ "rva": r, "code": c })),
                _ => Err(format!("no decompilation for {r:#x}")),
            }
        }
        "disasm" => {
            let r = rva().ok_or("disasm: missing/bad rva")?;
            let count = msg.get("count").and_then(Value::as_u64).unwrap_or(64) as usize;
            let idx = engine
                .index_for_rva(r)
                .ok_or_else(|| format!("no instruction at or after {r:#x}"))?;
            let out: Vec<Value> = engine
                .disasm_range(idx, count)
                .iter()
                .map(|i| json!({ "rva": i.rva, "mnemonic": i.mnemonic, "operands": i.operands }))
                .collect();
            Ok(Value::Array(out))
        }
        "xrefs" => {
            let r = rva().ok_or("xrefs: missing/bad rva")?;
            let out: Vec<Value> = engine
                .xrefs_to(r)
                .iter()
                .map(|x| json!({ "from": x.from_rva, "to": x.to_rva, "kind": x.kind }))
                .collect();
            Ok(Value::Array(out))
        }
        "rename" => {
            let r = rva().ok_or("rename: missing/bad rva")?;
            let name = msg.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                return Err("rename: missing 'name'".into());
            }
            engine.set_func_annotation(r, name, "");
            Ok(json!({ "ok": true }))
        }
        "comment" => {
            let r = rva().ok_or("comment: missing/bad rva")?;
            let text = msg.get("text").and_then(Value::as_str).unwrap_or("");
            engine.set_func_annotation(r, "", text);
            Ok(json!({ "ok": true }))
        }
        "set_var_type" => {
            let r = rva().ok_or("set_var_type: missing/bad rva")?;
            let var = msg.get("var").and_then(Value::as_str).unwrap_or("");
            let ty = msg.get("type").and_then(Value::as_str).unwrap_or("");
            if var.is_empty() {
                return Err("set_var_type: missing 'var'".into());
            }
            engine.set_var_type(r, var, ty);
            Ok(json!({ "ok": true }))
        }
        // Same derivation as the GUI's get_problems, exposed here so the Problems
        // pane's contents can be verified headlessly rather than by eye.
        "problems" => {
            let mut out: Vec<Value> = Vec::new();
            let funcs = engine.functions();
            for f in funcs.iter() {
                if f.block_count == 0 || f.size == 0 {
                    out.push(json!({ "kind": "no-code", "rva": f.rva, "func": f.name,
                                     "text": format!("no basic block recovered for {}", f.name) }));
                }
            }
            let total = engine.instruction_count();
            for i in engine.disasm_range(0, total).iter() {
                let m = i.mnemonic.as_str();
                let indirect = (m == "call" || m == "jmp")
                    && (i.operands.starts_with('[')
                        || i.operands.starts_with("qword")
                        || i.operands.starts_with("dword")
                        || i.operands.starts_with('r')
                        || i.operands.starts_with('e'));
                if !matches!(i.ref_type, 1 | 2 | 4) && indirect && i.ref_target.is_none() {
                    let fname = funcs
                        .iter()
                        .rev()
                        .find(|f| i.rva >= f.rva && i.rva < f.rva + f.size.max(1))
                        .map(|f| f.name.clone())
                        .unwrap_or_else(|| "<no function>".into());
                    out.push(json!({ "kind": "indirect-unresolved", "rva": i.rva, "func": fname,
                                     "text": format!("indirect {m} target unresolved ({})", i.operands) }));
                }
            }
            out.sort_by_key(|v| v.get("rva").and_then(Value::as_u64).unwrap_or(0));
            Ok(json!({ "count": out.len(), "items": out }))
        }
        "frame" => {
            let r = rva().ok_or("frame: missing/bad rva")?;
            let out: Vec<Value> = engine
                .frame(r)
                .iter()
                .map(|(off, name, ty)| json!({ "off": off, "name": name, "type": ty }))
                .collect();
            Ok(Value::Array(out))
        }
        "define_struct" => {
            let name = msg.get("name").and_then(Value::as_str).unwrap_or("");
            let body = msg.get("body").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                return Err("define_struct: missing 'name'".into());
            }
            engine.define_struct(name, body);
            Ok(json!({ "ok": true }))
        }
        "save_annotations" => {
            let p = msg.get("path").and_then(Value::as_str).unwrap_or("");
            if p.is_empty() {
                return Err("save_annotations: missing 'path'".into());
            }
            engine.save_annotations(p).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true }))
        }
        "load_annotations" => {
            let p = msg.get("path").and_then(Value::as_str).unwrap_or("");
            if p.is_empty() {
                return Err("load_annotations: missing 'path'".into());
            }
            engine.load_annotations(p).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true }))
        }
        "" => Err("missing 'cmd'".into()),
        other => Err(format!("unknown cmd '{other}'")),
    }
}

/// `--script <binary> [commands.jsonl|-]`. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let bin = match args.first() {
        Some(b) => b.clone(),
        None => {
            eprintln!("usage: disasmstudio --script <binary> [commands.jsonl|-]");
            return 2;
        }
    };
    let mut engine = match build_engine(&bin) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fatal: {e}");
            return 1;
        }
    };

    let src: Box<dyn BufRead> = match args.get(1).map(String::as_str) {
        None | Some("-") => Box::new(std::io::stdin().lock()),
        Some(p) => match std::fs::File::open(p) {
            Ok(f) => Box::new(std::io::BufReader::new(f)),
            Err(e) => {
                eprintln!("fatal: open {p}: {e}");
                return 1;
            }
        },
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut failures = 0i32;
    for line in src.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("read: {e}");
                break;
            }
        };
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue; // blank + `#` comments, so a script file stays readable
        }
        let reply = match serde_json::from_str::<Value>(t) {
            Ok(msg) => match run_cmd(&mut engine, &msg) {
                Ok(v) => json!({ "ok": true, "result": v }),
                Err(e) => {
                    failures += 1;
                    json!({ "ok": false, "error": e })
                }
            },
            Err(e) => {
                failures += 1;
                json!({ "ok": false, "error": format!("bad json: {e}") })
            }
        };
        if writeln!(out, "{reply}").is_err() {
            break; // downstream closed the pipe (script exited early)
        }
        let _ = out.flush();
    }
    i32::from(failures > 0)
}
