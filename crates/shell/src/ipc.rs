//! Per-window IPC dispatch.
//!
//! Each OS window installs its own wry IPC handler that captures a `RoleCtx`
//! (the proxy + that window's role-specific state) and this window's
//! `WindowId`. JS posts `{id, cmd, ...params}` (params are FLAT on the envelope,
//! not nested); we route by role + command and reply by sending
//! `UserEvent::Ipc { target, js }` back to the *originating* window, where `js`
//! evaluates `window.__IPC_EVENT__(<payload>)`.
//!
//! The reply `id` is echoed back **verbatim** as the original JSON value (the
//! frontend assigns numeric ids and matches them with strict equality), so it is
//! preserved as a `serde_json::Value` rather than coerced to a string.
//!
//! Window-creating commands (`new_project`, `open_project_dialog`,
//! `open_binary`) emit the matching `UserEvent` (`NewProject` / `OpenProjectFile`
//! / `OpenBinary`) and reply `{ok:true}` / `{opened}`. Native dialogs run rfd on
//! a spawned thread and reply through the proxy. Disasm query commands read the
//! captured `Session`; comment/mark edits mutate the captured `ProjectState`
//! and persist immediately.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tao::event_loop::EventLoopProxy;
use tao::window::WindowId;

use crate::dsproj::ProjectState;
use crate::session::{Row, SharedSession};
use crate::{dialogs, UserEvent};

/// What a window is. Carried by the window manager and the IPC handler.
/// `proj_path` is retained for diagnostics / future routing even when unread.
#[derive(Clone)]
#[allow(dead_code)]
pub enum Role {
    Launcher,
    Project { proj_path: String },
    Disasm,
}

/// Role-specific IPC context captured by a window's handler at build time.
#[allow(dead_code)]
pub enum RoleCtx {
    Launcher {
        proxy: EventLoopProxy<UserEvent>,
    },
    Project {
        proxy: EventLoopProxy<UserEvent>,
        proj: Arc<Mutex<ProjectState>>,
        proj_path: String,
    },
    Disasm {
        proxy: EventLoopProxy<UserEvent>,
        session: SharedSession,
        proj: Arc<Mutex<ProjectState>>,
        bin_id: u64,
    },
}

impl RoleCtx {
    pub fn proxy(&self) -> &EventLoopProxy<UserEvent> {
        match self {
            RoleCtx::Launcher { proxy } => proxy,
            RoleCtx::Project { proxy, .. } => proxy,
            RoleCtx::Disasm { proxy, .. } => proxy,
        }
    }
}

/// Lock a mutex, recovering the inner value on poison so we never panic.
fn lock<'a, T>(m: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Serializes on-demand (`get_pseudocode` slow-path) decompiles, which run off
/// the UI thread. Only ONE runs at a time so the process-global `DS_FORCE_SM` /
/// `DS_LINE_ADDR` env vars the engine reads can't race across concurrent
/// requests. The eager load-time pass never contends this (it runs before any
/// interactive request and never sets `DS_FORCE_SM`).
fn ondemand_guard() -> std::sync::MutexGuard<'static, ()> {
    static ONDEMAND: Mutex<()> = Mutex::new(());
    match ONDEMAND.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Entry point: parse the envelope and route by role.
pub fn dispatch(ctx: &RoleCtx, win: WindowId, body: &str) {
    let msg: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        // No id to reply to in a malformed envelope; drop silently.
        Err(_) => return,
    };
    // Preserve the id exactly as sent (numeric in the frontend).
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let cmd = msg.get("cmd").and_then(Value::as_str).unwrap_or("");

    match ctx {
        RoleCtx::Launcher { .. } => dispatch_launcher(ctx, win, &id, cmd, &msg),
        RoleCtx::Project { .. } => dispatch_project(ctx, win, &id, cmd, &msg),
        RoleCtx::Disasm { .. } => dispatch_disasm(ctx, win, &id, cmd, &msg),
    }
}

// ---- LAUNCHER ---------------------------------------------------------------

fn dispatch_launcher(ctx: &RoleCtx, win: WindowId, id: &Value, cmd: &str, msg: &Value) {
    match cmd {
        "list_recent_projects" => {
            let list = crate::dsproj::list_recent();
            reply_ok(ctx, win, id, to_val(&list));
        }
        "new_project" => {
            let name = msg
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                reply_err(ctx, win, id, "project name is required");
                return;
            }
            let _ = ctx.proxy().send_event(UserEvent::NewProject { name });
            reply_ok(ctx, win, id, json!({ "ok": true }));
        }
        "open_project_dialog" => {
            // Run the native dialog off the UI thread; reply through the proxy.
            let proxy = ctx.proxy().clone();
            let id = id.clone();
            std::thread::spawn(move || match dialogs::open_project() {
                Some(path) => {
                    let _ = proxy.send_event(UserEvent::OpenProjectFile { path });
                    send_reply(&proxy, win, &id, Ok(json!({ "opened": true })));
                }
                None => send_reply(&proxy, win, &id, Ok(json!({ "opened": false }))),
            });
        }
        "open_project_path" => {
            // Open a specific recent project directly (no dialog).
            let path = msg
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if path.is_empty() {
                reply_err(ctx, win, id, "project path is required");
                return;
            }
            let _ = ctx.proxy().send_event(UserEvent::OpenProjectFile { path });
            reply_ok(ctx, win, id, json!({ "ok": true }));
        }
        "ping" => reply_ok(ctx, win, id, json!({ "pong": true })),
        "" => reply_err(ctx, win, id, "missing 'cmd' field"),
        other => reply_err(ctx, win, id, &format!("unknown launcher command: {other}")),
    }
}

// ---- PROJECT ----------------------------------------------------------------

fn dispatch_project(ctx: &RoleCtx, win: WindowId, id: &Value, cmd: &str, msg: &Value) {
    let (proj, proj_path) = match ctx {
        RoleCtx::Project {
            proj, proj_path, ..
        } => (proj.clone(), proj_path.clone()),
        _ => return,
    };

    match cmd {
        "get_project" => {
            let s = lock(&proj);
            reply_ok(
                ctx,
                win,
                id,
                json!({
                    "name": s.proj.name,
                    "path": s.path,
                    "binaries": s.binaries_json(),
                }),
            );
        }
        "add_binary" => {
            // Native dialog off-thread; mutate + save on the worker, then reply.
            let proxy = ctx.proxy().clone();
            let id = id.clone();
            std::thread::spawn(move || {
                let data = match dialogs::open_binary() {
                    Some(path) => {
                        let mut s = lock(&proj);
                        s.add_binary(&path);
                        let save = s.save();
                        let list = s.binaries_json();
                        drop(s);
                        match save {
                            Ok(()) => Ok(json!({ "binaries": list })),
                            Err(e) => Err(format!("save project: {e}")),
                        }
                    }
                    // Cancelled: return the unchanged list.
                    None => {
                        let s = lock(&proj);
                        Ok(json!({ "binaries": s.binaries_json() }))
                    }
                };
                send_reply(&proxy, win, &id, data);
            });
        }
        "remove_binary" => {
            let bin_id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
            let mut s = lock(&proj);
            s.remove_binary(bin_id);
            let save = s.save();
            let list = s.binaries_json();
            drop(s);
            match save {
                Ok(()) => reply_ok(ctx, win, id, json!({ "binaries": list })),
                Err(e) => reply_err(ctx, win, id, &format!("save project: {e}")),
            }
        }
        "open_binary" => {
            let bin_id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
            let exists = {
                let s = lock(&proj);
                s.binary(bin_id).is_some()
            };
            if !exists {
                reply_err(ctx, win, id, "no such binary in project");
                return;
            }
            let _ = ctx.proxy().send_event(UserEvent::OpenBinary {
                proj_path: proj_path.clone(),
                bin_id,
            });
            reply_ok(ctx, win, id, json!({ "ok": true }));
        }
        "ping" => reply_ok(ctx, win, id, json!({ "pong": true })),
        "" => reply_err(ctx, win, id, "missing 'cmd' field"),
        other => reply_err(ctx, win, id, &format!("unknown project command: {other}")),
    }
}

// ---- DISASM -----------------------------------------------------------------

fn dispatch_disasm(ctx: &RoleCtx, win: WindowId, id: &Value, cmd: &str, msg: &Value) {
    let (session, proj, bin_id) = match ctx {
        RoleCtx::Disasm {
            session,
            proj,
            bin_id,
            ..
        } => (session.clone(), proj.clone(), *bin_id),
        _ => return,
    };
    let rva = || msg.get("rva").and_then(Value::as_u64).unwrap_or(0);

    match cmd {
        "get_session_info" => {
            let s = lock(&session);
            reply_ok(
                ctx,
                win,
                id,
                json!({
                    "name": s.binary_name,
                    "path": s.binary_path,
                    "project": s.project_name,
                }),
            );
        }
        "cancel_analysis" => {
            let s = lock(&session);
            s.cancel.store(true, Ordering::SeqCst);
            reply_ok(ctx, win, id, json!({ "ok": true }));
        }
        "get_binary_meta" => {
            let s = lock(&session);
            match s.meta.as_ref() {
                Some(meta) => reply_ok(
                    ctx,
                    win,
                    id,
                    json!({
                        "name": s.binary_name,
                        "path": s.binary_path,
                        "format": meta.format,
                        "arch": crate::session::arch_label(meta.arch),
                        "base": meta.base,
                        "entry": meta.entry,
                        "image_size": meta.image_size,
                        "segment_count": meta.segment_count,
                        "function_count": meta.function_count,
                        "instruction_count": meta.instruction_count,
                        "listing_len": s.listing_len,
                    }),
                ),
                None => reply_err(ctx, win, id, "analysis not ready"),
            }
        }
        "get_functions" => {
            let s = lock(&session);
            let arr: Vec<Value> = s
                .funcs
                .iter()
                .map(|f| {
                    json!({
                        "rva": f.rva,
                        "name": f.name,
                        "size": f.size,
                        "block_count": f.block_count,
                        "call_count": f.call_count,
                    })
                })
                .collect();
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_segments" => {
            let s = lock(&session);
            let arr: Vec<Value> = s
                .segs
                .iter()
                .map(|seg| {
                    let r = seg.flags & 1 != 0;
                    let w = seg.flags & 2 != 0;
                    let x = seg.flags & 4 != 0;
                    json!({
                        "name": seg.name,
                        "rva": seg.rva,
                        "size": seg.size,
                        "flags": seg.flags,
                        "r": r, "w": w, "x": x,
                    })
                })
                .collect();
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_exports" => {
            let s = lock(&session);
            let arr: Vec<Value> = s
                .exports
                .iter()
                .map(|(rva, name)| json!({ "rva": rva, "name": name }))
                .collect();
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_imports" => {
            let s = lock(&session);
            let arr: Vec<Value> = s
                .imports
                .iter()
                .map(|(rva, name, dll)| json!({ "rva": rva, "name": name, "dll": dll }))
                .collect();
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_strings" => {
            let s = lock(&session);
            let arr: Vec<Value> = s
                .strings
                .iter()
                .map(|(rva, value, kind)| json!({ "rva": rva, "value": value, "kind": kind }))
                .collect();
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_listing_len" => {
            let s = lock(&session);
            reply_ok(ctx, win, id, json!({ "len": s.listing_len }));
        }
        "get_disassembly" => {
            let start = msg.get("start").and_then(Value::as_u64).unwrap_or(0) as usize;
            let count = msg.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
            let s = lock(&session);
            let rows = render_rows(&s, start, count);
            reply_ok(ctx, win, id, Value::Array(rows));
        }
        "get_row_for_rva" => {
            let r = rva();
            let s = lock(&session);
            let idx = s.row_for_rva(r).map(|i| i as i64).unwrap_or(-1);
            reply_ok(ctx, win, id, json!({ "index": idx }));
        }
        "get_xrefs_to" => {
            let r = rva();
            let s = lock(&session);
            let mut arr: Vec<Value> = match s.engine.as_ref() {
                Some(e) => e
                    .xrefs_to(r)
                    .into_iter()
                    .map(|x| json!({ "from_rva": x.from_rva, "to_rva": x.to_rva, "type": x.kind }))
                    .collect(),
                None => Vec::new(),
            };
            // Supplement with data-pointer references (type 3 = DATA).
            if let Some(froms) = s.data_xrefs.get(&r) {
                for &from in froms {
                    arr.push(json!({ "from_rva": from, "to_rva": r, "type": 3 }));
                }
            }
            reply_ok(ctx, win, id, Value::Array(arr));
        }
        "get_pseudocode" => {
            let r = rva();
            // Per-function state-machine toggle: the UI's inline "0 gotos" button sends
            // `sm: true`, which forces the `while(1) switch(__state)` form for THIS function
            // only. The engine reads DS_FORCE_SM at decompile time; set it around this single
            // interactive call (one at a time on the UI thread -- no race with the N-thread
            // batch dumper, which never sets it).
            let sm = msg.get("sm").and_then(Value::as_bool).unwrap_or(false);
            // Fast path: the worker eagerly decompiled every function at load time
            // (structured form, `/*@addr*/` markers embedded). Serve that instantly.
            // The state-machine form (`sm`) is rare and not cached -> compute below.
            let cached = if !sm {
                lock(&session).decomp_cache.get(&r).cloned()
            } else {
                None
            };
            if let Some(c) = cached {
                reply_ok(ctx, win, id, json!({ "code": c }));
                return;
            }
            // Slow path: NOT cached — a function past the eager caps (a huge/pathological
            // CFG) or the interactive state-machine form. Decompile OFF the IPC/UI thread
            // and reply asynchronously, so a multi-second decompile can NEVER freeze the
            // app. The engine is shared (Arc, re-entrant) so we clone the handle and
            // release the session lock before the (potentially long) decompile. On-demand
            // decompiles are serialized by ondemand_guard() so the process-global
            // DS_FORCE_SM / DS_LINE_ADDR env vars can't race across concurrent requests.
            let engine = lock(&session).engine.clone();
            let session2 = session.clone();
            let proxy = ctx.proxy().clone();
            let id = id.clone();
            std::thread::spawn(move || {
                let result = match engine {
                    Some(e) => {
                        let _guard = ondemand_guard();
                        let had_sm = std::env::var("DS_FORCE_SM").ok();
                        if sm {
                            std::env::set_var("DS_FORCE_SM", "1");
                        }
                        std::env::set_var("DS_LINE_ADDR", "1"); // markers always on for the UI
                        let out = e.decompile(r);
                        match had_sm {
                            Some(v) => std::env::set_var("DS_FORCE_SM", v),
                            None => std::env::remove_var("DS_FORCE_SM"),
                        }
                        out
                    }
                    None => None,
                };
                // HONEST failure: when the engine genuinely can't produce a body, say so
                // as an ERROR the UI surfaces — never a blank body dressed up as success.
                match result {
                    Some(code) if !code.trim().is_empty() => {
                        if !sm {
                            lock(&session2).decomp_cache.insert(r, code.clone());
                        }
                        send_reply(&proxy, win, &id, Ok(json!({ "code": code })));
                    }
                    Some(_) => send_reply(
                        &proxy,
                        win,
                        &id,
                        Err(format!("decompilation produced no output for {r:#x}")),
                    ),
                    None => send_reply(
                        &proxy,
                        win,
                        &id,
                        Err(format!("no function at {r:#x} (decompilation unavailable)")),
                    ),
                }
            });
        }
        "set_comment" => {
            let r = rva();
            let text = msg.get("text").and_then(Value::as_str).unwrap_or("");
            let mut p = lock(&proj);
            p.set_comment(bin_id, r, text);
            let save = p.save();
            drop(p);
            match save {
                Ok(()) => reply_ok(ctx, win, id, json!({ "ok": true })),
                Err(e) => reply_err(ctx, win, id, &format!("save project: {e}")),
            }
        }
        "get_comments" => {
            let p = lock(&proj);
            reply_ok(ctx, win, id, p.comments_json(bin_id));
        }
        // Persist the decompilation to disk (Ctrl+S). Reopening this binary then
        // loads it instead of re-running the decompile pass.
        "save_analysis" => {
            let s = lock(&session);
            let path = s.binary_path.clone();
            let res = crate::session::save_decomp_cache(&path, &s.decomp_cache);
            drop(s);
            match res {
                Ok(count) => reply_ok(ctx, win, id, json!({ "ok": true, "count": count })),
                Err(e) => reply_err(ctx, win, id, &format!("save analysis: {e}")),
            }
        }
        "toggle_mark" => {
            let r = rva();
            let mut p = lock(&proj);
            let marked = p.toggle_mark(bin_id, r);
            let save = p.save();
            drop(p);
            match save {
                Ok(()) => reply_ok(ctx, win, id, json!({ "marked": marked })),
                Err(e) => reply_err(ctx, win, id, &format!("save project: {e}")),
            }
        }
        "get_marks" => {
            let p = lock(&proj);
            reply_ok(ctx, win, id, to_val(p.marks_vec(bin_id)));
        }
        "ping" => reply_ok(ctx, win, id, json!({ "pong": true })),
        "" => reply_err(ctx, win, id, "missing 'cmd' field"),
        other => reply_err(ctx, win, id, &format!("unknown disasm command: {other}")),
    }
}

/// Render listing rows `[start, start+count)` into IPC JSON. Data rows pull
/// their bytes from the engine; out-of-range / missing indices are skipped.
fn render_rows(s: &crate::session::Session, start: usize, count: usize) -> Vec<Value> {
    let total = s.rows.len();
    if start >= total || count == 0 {
        return Vec::new();
    }
    let end = start.saturating_add(count).min(total);

    let mut out: Vec<Value> = Vec::with_capacity(end - start);
    for row in &s.rows[start..end] {
        let v = match *row {
            Row::Seg(i) => match s.segs.get(i) {
                Some(seg) => {
                    let r = seg.flags & 1 != 0;
                    let w = seg.flags & 2 != 0;
                    let x = seg.flags & 4 != 0;
                    json!({
                        "kind": "segment",
                        "name": seg.name, "rva": seg.rva, "size": seg.size,
                        "flags": seg.flags, "r": r, "w": w, "x": x,
                    })
                }
                None => continue,
            },
            Row::Func(i) => match s.funcs.get(i) {
                Some(f) => json!({
                    "kind": "func",
                    "rva": f.rva, "name": f.name, "size": f.size,
                    "block_count": f.block_count,
                }),
                None => continue,
            },
            Row::Insn(insn_index) => {
                let engine = match s.engine.as_ref() {
                    Some(e) => e,
                    None => continue,
                };
                let insns = engine.disasm_range(insn_index, 1);
                match insns.first() {
                    Some(insn) => {
                        let ref_target = match insn.ref_target {
                            Some(t) if t != 0 => Value::from(t),
                            _ => Value::Null,
                        };
                        json!({
                            "kind": "insn",
                            "index": insn_index,
                            "rva": insn.rva,
                            "bytes": hex_bytes(&insn.bytes),
                            "mnemonic": insn.mnemonic,
                            "operands": insn.operands,
                            "ref_target": ref_target,
                            "ref_type": insn.ref_type,
                        })
                    }
                    None => continue,
                }
            }
            Row::Data { rva, len } => {
                let bytes = s
                    .engine
                    .as_ref()
                    .map(|e| e.read_bytes(rva, len as usize))
                    .unwrap_or_default();
                let hex = bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii: String = bytes
                    .iter()
                    .map(|&b| {
                        if (0x20..=0x7e).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                json!({
                    "kind": "data",
                    "rva": rva,
                    "bytes": hex,
                    "ascii": ascii,
                    "len": bytes.len(),
                })
            }
        };
        out.push(v);
    }
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---- reply helpers ----------------------------------------------------------

fn to_val<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn reply_ok(ctx: &RoleCtx, win: WindowId, id: &Value, data: Value) {
    send_reply(ctx.proxy(), win, id, Ok(data));
}

fn reply_err(ctx: &RoleCtx, win: WindowId, id: &Value, message: &str) {
    send_reply(ctx.proxy(), win, id, Err(message.to_string()));
}

/// Build a `{id,ok,data}` / `{id,ok:false,error}` payload and route it to the
/// originating window via the proxy. `id` is echoed back verbatim.
fn send_reply(
    proxy: &EventLoopProxy<UserEvent>,
    win: WindowId,
    id: &Value,
    result: Result<Value, String>,
) {
    let payload = match result {
        Ok(data) => json!({ "id": id, "ok": true, "data": data }),
        Err(message) => json!({ "id": id, "ok": false, "error": message }),
    };
    let js = format!("window.__IPC_EVENT__({payload})");
    let _ = proxy.send_event(UserEvent::Ipc { target: win, js });
}
