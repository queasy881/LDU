//! A per-disasm-window analysis session.
//!
//! Each DISASM window owns one `Session` behind an `Arc<Mutex<…>>`. Analysis
//! runs the same 5-stage pipeline as the original single-window `app.rs`, but it
//! now pushes progress / completion events to *this* window via the event-loop
//! proxy (`UserEvent::Ipc { target, js }`) instead of broadcasting globally.
//!
//! `bridge::Engine` is `unsafe impl Send`, so — unlike the reference `d` project
//! — the engine is built directly on the worker thread and the finished result
//! is committed into the shared `Session` under its `Mutex`, exactly like
//! `app.rs::run_analysis`. No separate UI-thread finalize step is required.
//!
//! After analysis the session holds a flat **listing**: a `Vec<Row>` walking the
//! image in RVA order — segment banners, function banners, instruction rows, and
//! 16-byte hex/ascii **data** rows for gaps and non-executable / empty segments —
//! plus a `BTreeMap<rva, row-index>` for at-or-after address lookups.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tao::event_loop::EventLoopProxy;
use tao::window::WindowId;

use binparser::{Arch as PArch, BinaryMeta, Format};
use bridge::{Arch as BArch, Engine, Func, Meta, Segment};

use crate::UserEvent;

pub type SharedSession = Arc<Mutex<Session>>;

/// One row in the flat listing. Banners reference indices into `segs` / `funcs`;
/// instruction rows reference an engine instruction index; data rows carry their
/// own rva + byte length.
#[derive(Debug, Clone, Copy)]
pub enum Row {
    /// Index into `segs`.
    Seg(usize),
    /// Index into `funcs`.
    Func(usize),
    /// Engine instruction index.
    Insn(usize),
    /// A run of raw bytes with no decoded instruction (gap / data section).
    Data { rva: u64, len: u32 },
}

/// Lightweight binary metadata snapshot mirrored for cheap IPC reads (kept after
/// analysis so replies never need to touch the engine for metadata).
#[derive(Debug, Clone)]
pub struct MetaSnapshot {
    pub format: String,
    pub arch: u32,
    pub base: u64,
    pub entry: u64,
    pub image_size: u64,
    pub segment_count: usize,
    pub function_count: usize,
    pub instruction_count: usize,
}

/// A parsed + analyzed binary plus the data needed to drive one disasm window.
pub struct Session {
    pub proxy: EventLoopProxy<UserEvent>,
    /// The window this session pushes events to.
    pub target: WindowId,
    pub cancel: Arc<AtomicBool>,

    pub binary_path: String,
    pub binary_name: String,
    pub project_name: String,

    /// Snapshot of binary metadata (kept after analysis for fast IPC replies).
    pub meta: Option<MetaSnapshot>,
    /// The `Send` decompiler engine; built on the worker thread.
    /// Shared behind an `Arc` so an on-demand `get_pseudocode` can clone the
    /// handle and decompile OFF the IPC/UI thread (the engine is `Sync` and
    /// re-entrant) without holding the session lock for the whole decompile — a
    /// large/pathological function then never freezes the app.
    pub engine: Option<Arc<Engine>>,

    pub funcs: Vec<Func>,
    pub segs: Vec<Segment>,
    /// Export table: (rva, name), sorted by rva.
    pub exports: Vec<(u64, String)>,
    /// Import table: (IAT slot rva, name, dll), sorted by (dll, name). `dll` is
    /// the owning module (e.g. `"USER32.dll"`) or empty when unknown.
    pub imports: Vec<(u64, String, String)>,
    /// Extracted strings: (rva, value, kind) where kind 0=ascii, 1=utf-16.
    pub strings: Vec<(u64, String, u8)>,
    /// Data-pointer cross-references: target rva -> the data slots that hold a
    /// pointer to it. Supplements the engine's instruction xrefs so that things
    /// referenced only through pointer tables (vtables, ImGui name arrays, …)
    /// still have xrefs.
    pub data_xrefs: HashMap<u64, Vec<u64>>,
    pub rows: Vec<Row>,
    /// Sorted (rva -> listing row) map for nearest-at-or-after lookups.
    pub rva_index: BTreeMap<u64, usize>,
    pub listing_len: usize,
    /// Eagerly-decompiled functions: rva -> pseudocode (with `/*@addr*/` line
    /// markers). Built on the worker thread at load time so get_pseudocode is
    /// instant; on-demand misses are inserted here too.
    pub decomp_cache: HashMap<u64, String>,
}

impl Session {
    pub fn new(
        proxy: EventLoopProxy<UserEvent>,
        target: WindowId,
        binary_path: String,
        binary_name: String,
        project_name: String,
    ) -> Session {
        Session {
            proxy,
            target,
            cancel: Arc::new(AtomicBool::new(false)),
            binary_path,
            binary_name,
            project_name,
            meta: None,
            engine: None,
            funcs: Vec::new(),
            segs: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            strings: Vec::new(),
            data_xrefs: HashMap::new(),
            rows: Vec::new(),
            rva_index: BTreeMap::new(),
            listing_len: 0,
            decomp_cache: HashMap::new(),
        }
    }

    /// Listing index at-or-after `rva`, or `None` if past the end.
    pub fn row_for_rva(&self, rva: u64) -> Option<usize> {
        self.rva_index.range(rva..).next().map(|(_, &idx)| idx)
    }
}

// ---- event helpers ----------------------------------------------------------

/// Push a JS snippet to the session's window (best-effort).
fn push(proxy: &EventLoopProxy<UserEvent>, target: WindowId, js: String) {
    let _ = proxy.send_event(UserEvent::Ipc { target, js });
}

/// Emit a push event object `{event:"...",...}` to the session's window.
fn push_event(proxy: &EventLoopProxy<UserEvent>, target: WindowId, value: serde_json::Value) {
    push(proxy, target, format!("window.__IPC_EVENT__({value})"));
}

fn progress(proxy: &EventLoopProxy<UserEvent>, target: WindowId, stage: &str, pct: f64) {
    push_event(
        proxy,
        target,
        serde_json::json!({ "event": "analysis_progress", "stage": stage, "pct": pct }),
    );
}

/// On-disk decompilation cache so reopening a binary skips the (long) decompile
/// pass. Keyed by a hash of the binary's absolute path; validated on load against
/// the binary's size + mtime so a changed binary is re-analyzed, never stale.
fn analysis_cache_path(binary_path: &str) -> Option<std::path::PathBuf> {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let abs = std::fs::canonicalize(binary_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| binary_path.to_string());
    // FNV-1a over the absolute path -> stable per-binary filename.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in abs.to_lowercase().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    Some(base.join("disasmstudio").join("cache").join(format!("{h:016x}.dsa")))
}
/// (size, mtime-secs) stamp used to invalidate a stale cache.
/// A stamp that changes whenever the decompiler engine changes: the app exe's
/// own mtime. Rebuilding the app (which recompiles the engine) invalidates every
/// saved decompilation cache automatically, so a Ctrl+S cache from an older,
/// buggier engine is never replayed (that served stale 739-goto output).
fn engine_ver() -> u64 {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn bin_stamp(path: &str) -> (u64, u64) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            (m.len(), mtime)
        }
        Err(_) => (0, 0),
    }
}
/// Serialize the decompilation cache: magic, version, bin stamp, then
/// (rva:u64, len:u32, utf8) records. Returns the number of functions written.
pub fn save_decomp_cache(binary_path: &str, cache: &HashMap<u64, String>) -> Result<usize, String> {
    let cp = analysis_cache_path(binary_path).ok_or("no cache path")?;
    if let Some(parent) = cp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let (size, mtime) = bin_stamp(binary_path);
    let mut buf: Vec<u8> = Vec::with_capacity(cache.len() * 384 + 40);
    buf.extend_from_slice(b"DSAC");
    buf.push(2); // format v2: adds the engine-version stamp
    buf.extend_from_slice(&engine_ver().to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&mtime.to_le_bytes());
    buf.extend_from_slice(&(cache.len() as u32).to_le_bytes());
    for (rva, text) in cache {
        buf.extend_from_slice(&rva.to_le_bytes());
        let tb = text.as_bytes();
        buf.extend_from_slice(&(tb.len() as u32).to_le_bytes());
        buf.extend_from_slice(tb);
    }
    std::fs::write(&cp, &buf).map_err(|e| e.to_string())?;
    Ok(cache.len())
}
/// Load a previously-saved cache IFF the binary's size+mtime still match.
fn load_decomp_cache(binary_path: &str) -> Option<HashMap<u64, String>> {
    let cp = analysis_cache_path(binary_path)?;
    let buf = std::fs::read(&cp).ok()?;
    // v2 header: "DSAC"(4) ver=2(1) engine_ver(8) size(8) mtime(8) count(4) = 33
    if buf.len() < 33 || &buf[0..4] != b"DSAC" || buf[4] != 2 {
        return None;
    }
    let fever = u64::from_le_bytes(buf[5..13].try_into().ok()?);
    if fever != engine_ver() {
        return None; // decompiler engine changed since the cache was written
    }
    let (size, mtime) = bin_stamp(binary_path);
    let fsize = u64::from_le_bytes(buf[13..21].try_into().ok()?);
    let fmtime = u64::from_le_bytes(buf[21..29].try_into().ok()?);
    if fsize != size || fmtime != mtime {
        return None; // binary changed since the cache was written
    }
    let count = u32::from_le_bytes(buf[29..33].try_into().ok()?) as usize;
    let mut off = 33usize;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        if off + 12 > buf.len() {
            return None;
        }
        let rva = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
        off += 8;
        let len = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?) as usize;
        off += 4;
        if off + len > buf.len() {
            return None;
        }
        map.insert(rva, String::from_utf8_lossy(&buf[off..off + len]).into_owned());
        off += len;
    }
    Some(map)
}

/// Progress for a counted stage (e.g. decompiling N/total). `done`/`total` let the
/// overlay show a percentage that MATCHES the count instead of the overall bar value.
fn progress_count(
    proxy: &EventLoopProxy<UserEvent>,
    target: WindowId,
    stage: &str,
    pct: f64,
    done: usize,
    total: usize,
) {
    push_event(
        proxy,
        target,
        serde_json::json!({ "event": "analysis_progress", "stage": stage, "pct": pct, "done": done, "total": total }),
    );
}

// ---- FLIRT library-function naming ----------------------------------------
/// Locate the signature-database directory (`*.fdb`): $DS_FLIRT_DIR, then next to
/// the exe, then the dev repo layout, then the CWD.
fn flirt_sig_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("DS_FLIRT_DIR") {
        let p = std::path::PathBuf::from(d);
        if p.is_dir() {
            return Some(p);
        }
    }
    let mut cands: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cands.push(dir.join("flirt").join("sigs"));
            cands.push(dir.join("sigs"));
            if let Some(root) = dir.parent().and_then(|p| p.parent()) {
                cands.push(root.join("flirt").join("sigs")); // target/<profile>/exe -> repo
            }
        }
    }
    cands.push(std::path::PathBuf::from("flirt/sigs"));
    cands.into_iter().find(|p| p.is_dir())
}

/// Read up to `len` code bytes at `rva` from the on-disk file via the segment map.
fn read_rva_code(bytes: &[u8], segs: &[binparser::Segment], rva: u64, len: usize) -> Option<Vec<u8>> {
    for s in segs {
        if rva >= s.rva && rva < s.rva.saturating_add(s.vsize) {
            let fo = (s.file_off + (rva - s.rva)) as usize;
            if fo >= bytes.len() {
                return None;
            }
            let seg_end = (s.file_off + s.file_size) as usize;
            let end = (fo + len).min(seg_end).min(bytes.len());
            if end <= fo {
                return None;
            }
            return Some(bytes[fo..end].to_vec());
        }
    }
    None
}

/// Name unnamed (sub_) functions that match a library signature. Returns the count.
fn flirt_pass(engine: &mut Engine, funcs: &mut [Func], bytes: &[u8], segs: &[binparser::Segment]) -> usize {
    let dir = match flirt_sig_dir() {
        Some(d) => d,
        None => return 0,
    };
    let dbs = flirt::load_dir(&dir);
    if dbs.is_empty() {
        return 0;
    }
    let mut named = 0usize;
    for f in funcs.iter_mut() {
        if !f.name.is_empty() {
            continue; // keep exports / already-named
        }
        let want = (f.size as usize).clamp(6, 65536);
        let code = match read_rva_code(bytes, segs, f.rva, want) {
            Some(c) => c,
            None => continue,
        };
        for db in &dbs {
            if let Some(nm) = db.match_fn(&code, |_| None) {
                engine.add_symbol(f.rva, nm);
                f.name = nm.to_string();
                named += 1;
                break;
            }
        }
    }
    named
}

fn err_event(proxy: &EventLoopProxy<UserEvent>, target: WindowId, message: String) {
    push_event(
        proxy,
        target,
        serde_json::json!({ "event": "analysis_error", "message": message }),
    );
}

fn is_cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::SeqCst)
}

// ---- mapping helpers --------------------------------------------------------

pub fn map_arch(a: PArch) -> BArch {
    match a {
        PArch::X86 => BArch::X86,
        PArch::X64 => BArch::X64,
        PArch::Arm => BArch::Arm,
        PArch::Arm64 => BArch::Arm64,
        PArch::Unknown => BArch::X64,
    }
}

pub fn format_label(f: &Format) -> &'static str {
    match f {
        Format::Pe32 => "PE32",
        Format::Pe32Plus => "PE32+",
        Format::Elf32 => "ELF32",
        Format::Elf64 => "ELF64",
    }
}

pub fn arch_label(arch: u32) -> &'static str {
    match arch {
        0 => "x86",
        1 => "x64",
        2 => "ARM",
        3 => "ARM64",
        _ => "unknown",
    }
}

fn meta_snapshot(format: &Format, m: &Meta) -> MetaSnapshot {
    MetaSnapshot {
        format: format_label(format).to_string(),
        arch: m.arch,
        base: m.base,
        entry: m.entry,
        image_size: m.image_size,
        segment_count: m.segment_count,
        function_count: m.function_count,
        instruction_count: m.instruction_count,
    }
}

// ---- driver -----------------------------------------------------------------

/// Kick off analysis for `session` on a background thread. Progress, completion,
/// and error events all arrive on the event loop as `UserEvent::Ipc` addressed
/// to the session's `target` window. The worker is cancellable via
/// `session.cancel`; the finished engine + listing are committed under the
/// session `Mutex`, then `analysis_done` is pushed.
pub fn start_analysis(session: &SharedSession) {
    let (proxy, target, path, cancel) = {
        let s = match session.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        (
            s.proxy.clone(),
            s.target,
            s.binary_path.clone(),
            s.cancel.clone(),
        )
    };

    let session = session.clone();
    std::thread::spawn(move || {
        run_analysis(session, path, cancel, proxy, target);
    });
}

/// The full pipeline. Each stage checks the cancel flag; on cancellation it
/// quietly returns without emitting done/error.
fn run_analysis(
    session: SharedSession,
    path: String,
    cancel: Arc<AtomicBool>,
    proxy: EventLoopProxy<UserEvent>,
    target: WindowId,
) {
    // -- Stage 1: parse + build image + create engine + seed (0..20) ---------
    progress(&proxy, target, "Reading file", 0.0);

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            err_event(&proxy, target, format!("Failed to read file: {e}"));
            return;
        }
    };
    if is_cancelled(&cancel) {
        return;
    }
    progress(&proxy, target, "Parsing PE headers", 6.0);

    let parsed = match BinaryMeta::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            err_event(&proxy, target, format!("Parse error: {e}"));
            return;
        }
    };
    progress(&proxy, target, "Mapping image sections", 12.0);

    let image = parsed.build_image(&bytes);
    let barch = map_arch(parsed.arch);
    let format = parsed.format;

    let mut engine = Engine::new(image, parsed.base, barch);
    engine.set_is_dll(parsed.is_dll);
    engine.set_entry_rva(parsed.entry);
    // Let the PDB loader resolve a relative/bare CodeView filename (common with
    // Rust/MSVC) next to the binary instead of against the process CWD.
    if let Some(dir) = std::path::Path::new(&path).parent() {
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
    for &cb in &parsed.tls_callbacks {
        engine.add_entry(cb);
    }
    for imp in &parsed.imports {
        engine.add_import(imp.rva, &imp.name);
    }
    progress(
        &proxy,
        target,
        &format!(
            "Reading imports ({}) & exports ({})",
            parsed.imports.len(),
            parsed.exports.len()
        ),
        16.0,
    );

    // Retain the import/export tables for the sidebar (sorted for display).
    let mut exports: Vec<(u64, String)> = parsed
        .exports
        .iter()
        .map(|s| (s.rva, s.name.clone()))
        .collect();
    exports.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut imports: Vec<(u64, String, String)> = parsed
        .imports
        .iter()
        .map(|s| (s.rva, s.name.clone(), s.module.clone().unwrap_or_default()))
        .collect();
    // Group by DLL (case-insensitive), then by symbol name within each DLL.
    imports.sort_by(|a, b| {
        a.2.to_lowercase()
            .cmp(&b.2.to_lowercase())
            .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
    });

    progress(&proxy, target, "Seeding entry points", 20.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 2: disassemble + build CFG (20..50) ---------------------------
    progress(&proxy, target, "Disassembling", 22.0);
    if let Err(e) = engine.disassemble() {
        err_event(&proxy, target, format!("Disassembly failed: {e}"));
        return;
    }
    if is_cancelled(&cancel) {
        return;
    }
    progress(&proxy, target, "Building control-flow graph", 38.0);
    if let Err(e) = engine.build_cfg() {
        err_event(&proxy, target, format!("CFG construction failed: {e}"));
        return;
    }
    progress(&proxy, target, "Building CFG", 50.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 3: resolve symbols (50..70) -----------------------------------
    progress(&proxy, target, "Recovering symbols", 52.0);
    if let Err(e) = engine.resolve_symbols() {
        err_event(&proxy, target, format!("Symbol resolution failed: {e}"));
        return;
    }
    progress(&proxy, target, "Recovering symbols", 70.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 4: build xrefs (70..90) ---------------------------------------
    progress(&proxy, target, "Indexing cross-references", 72.0);
    if let Err(e) = engine.build_xrefs() {
        err_event(&proxy, target, format!("Xref indexing failed: {e}"));
        return;
    }
    progress(&proxy, target, "Indexing cross-references", 90.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 5: build listing + rva index (90..60?) ------------------------
    progress(&proxy, target, "Building listing", 55.0);
    let meta = engine.meta();
    let snapshot = meta_snapshot(&format, &meta);
    let segs = engine.segments();
    let mut funcs = engine.functions();
    // FLIRT: name statically-linked library functions (CRT/STL) from signature DBs.
    progress(&proxy, target, "Identifying library functions (FLIRT)", 54.0);
    let flirt_named = flirt_pass(&mut engine, &mut funcs, &bytes, &parsed.segments);
    if flirt_named > 0 {
        progress(
            &proxy,
            target,
            &format!("Identified {flirt_named} library functions (FLIRT)"),
            55.0,
        );
    }
    let (rows, rva_index, listing_len) = build_listing(&engine, &segs, &funcs);
    progress(&proxy, target, "Scanning strings", 58.0);
    let strings = scan_strings(&engine, &segs);
    progress(&proxy, target, "Indexing data pointers", 59.0);
    let data_xrefs = scan_pointers(&engine, &segs, meta.base, meta.image_size, meta.arch);
    progress(&proxy, target, "Finalizing", 60.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 6: eagerly decompile EVERY function (60..99) ------------------
    // Runs on THIS worker thread while it still owns `engine`, so it never
    // contends the session lock and the app window stays responsive (the
    // centered overlay animates the count). Results are cached so
    // get_pseudocode is instant afterwards. `/*@addr*/` line markers are on for
    // the listing<->decompiler sync. A per-function size/block guard plus a
    // wall-clock budget keep the load BOUNDED: a rare pathological function is
    // deferred to on-demand decompilation instead of stalling the whole load.
    // Fast path: a saved analysis (Ctrl+S last session) whose binary is unchanged.
    // Skip the whole decompile pass — the functions are already done.
    let decomp_cache = if let Some(cached) = load_decomp_cache(&path) {
        progress_count(
            &proxy,
            target,
            "Loaded saved decompilation",
            99.0,
            cached.len(),
            cached.len().max(1),
        );
        cached
    } else {
        std::env::set_var("DS_LINE_ADDR", "1");
        let total = funcs.len().max(1);
        let t0 = std::time::Instant::now();
        // Budget generously: the eager pass runs on THIS worker thread (UI stays
        // responsive), and anything it defers gets decompiled ON THE UI THREAD the
        // first time it's opened — which FREEZES the app on a big function (a 775-
        // block / 12KB function is ~5-7s). So decompile essentially everything up
        // front off-thread; only a truly pathological CFG past the raised caps or
        // the wall-clock budget still defers.
        let budget = std::time::Duration::from_secs(
            std::env::var("DS_DECOMPILE_BUDGET_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(240),
        );
        const BIG_BLOCKS: u32 = 4000; // only an extreme CFG defers now
        const BIG_SIZE: u64 = 0x40000;

        // PARALLEL decompile. ds_decompile is re-entrant (fresh Decompiler per call,
        // const engine, mutex-guarded per-engine caches — see bridge `unsafe impl
        // Sync for Engine`), so N worker threads share one `&engine` and each pulls
        // the next function index off a shared atomic. This is the throughput lever:
        // one core did ~a few hundred fns/s serially; every core in parallel clears
        // thousands/s so even a large image finishes inside the budget instead of
        // deferring functions to the (freeze-prone) on-open path.
        //
        // Warm the per-engine sig table ONCE up front (single-threaded) so the N
        // workers don't all block on the first-call build mutex at startup.
        // Thread count. The decompiler is allocation-heavy (every expression node is
        // a shared_ptr, every pass clones trees), so the Windows process heap lock —
        // NOT the CPU — is the ceiling: a measured scaling sweep on a 16-core box peaked
        // at ~8 workers (122 fns/s) and got SLOWER at 16 (115). So cap the default at 8;
        // that is at/near the throughput peak AND leaves cores free so the UI stays
        // responsive during the load. Overridable via DS_DECOMPILE_THREADS (raise it once
        // a scalable allocator lands — then scaling becomes near-linear). See
        // crates/shell/tests/throughput.rs.
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let nthreads = std::env::var("DS_DECOMPILE_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| cores.min(8))
            .min(total)
            .max(1);
        let next = AtomicUsize::new(0); // shared work cursor
        let done = AtomicUsize::new(0); // completed count, for progress
        let shards: Vec<Mutex<Vec<(u64, String)>>> =
            (0..nthreads).map(|_| Mutex::new(Vec::new())).collect();

        // Warm the per-engine sig table (the O(functions) prepass) once, single-
        // threaded, by decompiling any one eligible function and discarding it. The
        // sig table is then cached, so the N workers never contend on the build
        // mutex. The one redundant decompile is negligible (it reuses the cache).
        if let Some(f0) = funcs
            .iter()
            .find(|f| f.block_count <= BIG_BLOCKS && f.size <= BIG_SIZE)
        {
            let _ = engine.decompile(f0.rva);
        }

        let engine_ref = &engine;
        let funcs_ref = &funcs;
        let cancel_ref = &cancel;
        std::thread::scope(|scope| {
            for tid in 0..nthreads {
                let next = &next;
                let done = &done;
                let shard = &shards[tid];
                scope.spawn(move || {
                    let mut local: Vec<(u64, String)> = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= total || is_cancelled(cancel_ref) {
                            break;
                        }
                        let f = &funcs_ref[i];
                        // A pathological CFG past the raised caps, or the wall-clock
                        // budget, is DEFERRED (decompiled on demand, off the UI
                        // thread — see get_pseudocode). Everything else decompiles now.
                        if !(f.block_count > BIG_BLOCKS || f.size > BIG_SIZE || t0.elapsed() > budget)
                        {
                            if let Some(code) = engine_ref.decompile(f.rva) {
                                local.push((f.rva, code));
                            }
                        }
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    *shard.lock().unwrap_or_else(|p| p.into_inner()) = local;
                });
            }
            // Progress reporter runs on the scope's own thread while workers churn.
            loop {
                let d = done.load(Ordering::Relaxed).min(total);
                let pct = 60.0 + 39.0 * (d as f64 / total as f64);
                progress_count(&proxy, target, "Decompiling functions", pct, d, total);
                if d >= total || is_cancelled(cancel_ref) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(60));
            }
        });
        std::env::remove_var("DS_LINE_ADDR");
        if is_cancelled(&cancel) {
            return;
        }
        let mut cache: HashMap<u64, String> = HashMap::with_capacity(total);
        for shard in shards {
            for (rva, code) in shard.into_inner().unwrap_or_else(|p| p.into_inner()) {
                cache.insert(rva, code);
            }
        }
        cache
    };
    if is_cancelled(&cancel) {
        return;
    }

    // Commit into the shared session.
    {
        let mut s = match session.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };
        // If a newer run replaced our cancel token, or cancellation fired, bail.
        if !Arc::ptr_eq(&s.cancel, &cancel) || is_cancelled(&cancel) {
            return;
        }
        s.meta = Some(snapshot);
        s.engine = Some(Arc::new(engine));
        s.segs = segs;
        s.funcs = funcs;
        s.exports = exports;
        s.imports = imports;
        s.strings = strings;
        s.data_xrefs = data_xrefs;
        s.rows = rows;
        s.rva_index = rva_index;
        s.listing_len = listing_len;
        s.decomp_cache = decomp_cache;
    }

    push_event(&proxy, target, serde_json::json!({ "event": "analysis_done" }));
}

/// Scan mapped segments for printable strings: ASCII runs and UTF-16LE runs of
/// at least `MIN` chars. Returns (rva, value, kind) with kind 0=ascii, 1=utf16,
/// sorted by rva. Bounded so a huge image can't blow up memory.
fn scan_strings(engine: &Engine, segs: &[Segment]) -> Vec<(u64, String, u8)> {
    // Ghidra-parity string recovery. We deliberately DO NOT require a trailing NUL
    // (Ghidra reports any maximal printable run) and use min length 4, so we find
    // at least as many strings as Ghidra does. False positives are bounded by the
    // maximal-run model (a run is one string) and by only scanning data segments.
    const MIN: usize = 4;
    const MAX_VAL: usize = 480;
    const CAP: usize = 500_000;
    // Printable ASCII plus the common in-string whitespace bytes (tab / LF / CR),
    // so a `"...line1\nline2..."` format string stays ONE string instead of being
    // split at the 0x0a — matching Ghidra's default string char set.
    let printable = |b: u8| (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r';

    let mut out: Vec<(u64, String, u8)> = Vec::new();
    'segs: for seg in segs {
        if seg.size == 0 {
            continue;
        }
        // Skip executable segments: code bytes (push/pop sequences, etc.) produce
        // enormous amounts of false-positive "strings". Real strings live in data
        // sections (.rdata / .data / .rsrc).
        if seg.flags & 4 != 0 {
            continue;
        }
        let bytes = engine.read_bytes(seg.rva, seg.size as usize);
        let n = bytes.len();
        if n == 0 {
            continue;
        }

        // ASCII / UTF-8 runs — any maximal printable run of >= MIN bytes, no NUL
        // requirement.
        let mut i = 0usize;
        while i < n {
            if printable(bytes[i]) {
                let start = i;
                let mut j = i;
                while j < n && printable(bytes[j]) {
                    j += 1;
                }
                let len = j - start;
                if len >= MIN {
                    let take = len.min(MAX_VAL);
                    let s: String = bytes[start..start + take].iter().map(|&c| c as char).collect();
                    out.push((seg.rva + start as u64, s, 0));
                    if out.len() >= CAP {
                        break 'segs;
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }

        // UTF-16LE runs: [printable, 0x00] repeated — no wide-NUL requirement.
        let mut i = 0usize;
        while i + 1 < n {
            if printable(bytes[i]) && bytes[i + 1] == 0 {
                let start = i;
                let mut s = String::new();
                let mut j = i;
                while j + 1 < n && printable(bytes[j]) && bytes[j + 1] == 0 && s.len() < MAX_VAL {
                    s.push(bytes[j] as char);
                    j += 2;
                }
                if s.len() >= MIN {
                    out.push((seg.rva + start as u64, s, 1));
                    if out.len() >= CAP {
                        break 'segs;
                    }
                }
                i = j.max(i + 2);
            } else {
                i += 1;
            }
        }
    }
    // Sort by rva; collapse exact-duplicate addresses (an ASCII and wide run can
    // only coincide on empty edge cases, but be defensive).
    out.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.len().cmp(&a.1.len())));
    out.dedup_by_key(|(rva, _, _)| *rva);
    out
}

/// Scan readable (non-executable) data segments for aligned pointers that fall
/// inside the image, recording them as `to_rva -> [pointer-slot rva, ...]`. This
/// gives strings/functions/vtables that are referenced only through pointer
/// tables a usable cross-reference. Pointers are absolute VAs (base + rva).
fn scan_pointers(
    engine: &Engine,
    segs: &[Segment],
    base: u64,
    image_size: u64,
    arch: u32,
) -> HashMap<u64, Vec<u64>> {
    const CAP: usize = 2_000_000;
    let ptr: usize = if arch == 0 || arch == 2 { 4 } else { 8 }; // x86/arm32 -> 4
    let mut map: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut count = 0usize;

    for seg in segs {
        if seg.flags & 1 == 0 || seg.flags & 4 != 0 {
            continue; // readable + non-executable only
        }
        let bytes = engine.read_bytes(seg.rva, seg.size as usize);
        let n = bytes.len();
        let mut off = 0usize;
        while off + ptr <= n {
            let v = if ptr == 8 {
                u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
            } else {
                u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as u64
            };
            if v > base {
                let rva = v - base;
                if rva != 0 && rva < image_size {
                    map.entry(rva).or_default().push(seg.rva + off as u64);
                    count += 1;
                    if count >= CAP {
                        return map;
                    }
                }
            }
            off += ptr;
        }
    }
    map
}

const DATA_ROW: u64 = 16;

/// Flatten the image into banner + instruction + data rows and build the rva
/// index.
///
/// Walks SEGMENTS in rva order. For each segment a `Seg` banner is emitted, then
/// within `[seg.rva, seg.rva+size)`: a `Func` banner at any function start, an
/// `Insn` row where an instruction begins, and 16-byte `Data` rows for any byte
/// ranges with no instruction (and for whole non-executable / empty segments).
/// Every row's starting rva is indexed (a function start prefers its banner row).
fn build_listing(
    engine: &Engine,
    segs: &[Segment],
    funcs: &[Func],
) -> (Vec<Row>, BTreeMap<u64, usize>, usize) {
    // rva -> (instruction index, byte length). Built by streaming the whole
    // instruction listing once, in index order.
    let insn_count = engine.instruction_count();
    let mut insn_at: BTreeMap<u64, (usize, u64)> = BTreeMap::new();
    {
        const WINDOW: usize = 4096;
        let mut idx = 0usize;
        while idx < insn_count {
            let take = WINDOW.min(insn_count - idx);
            let batch = engine.disasm_range(idx, take);
            if batch.is_empty() {
                break;
            }
            for (k, insn) in batch.iter().enumerate() {
                let len = insn.bytes.len().max(1) as u64;
                insn_at.insert(insn.rva, (idx + k, len));
            }
            idx += batch.len();
            if batch.len() < take {
                break;
            }
        }
    }

    // rva -> function index.
    let mut func_by_rva: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, f) in funcs.iter().enumerate() {
        func_by_rva.insert(f.rva, i);
    }

    // Segments in rva order.
    let mut seg_order: Vec<usize> = (0..segs.len()).collect();
    seg_order.sort_by_key(|&i| segs[i].rva);

    // Image extent (so a bogus segment size can't walk off forever).
    let image_len = segs
        .iter()
        .map(|s| s.rva.saturating_add(s.size))
        .max()
        .unwrap_or(0);

    let mut rows: Vec<Row> = Vec::with_capacity(insn_count + segs.len() + funcs.len());
    let mut rva_index: BTreeMap<u64, usize> = BTreeMap::new();

    // Push a row, indexing its rva (first writer wins for a given rva).
    let push_row = |rows: &mut Vec<Row>, idx: &mut BTreeMap<u64, usize>, row: Row, rva: u64| {
        idx.entry(rva).or_insert(rows.len());
        rows.push(row);
    };

    for &si in &seg_order {
        let seg = &segs[si];
        let seg_rva = seg.rva;
        let seg_end = seg_rva
            .saturating_add(seg.size)
            .min(image_len.max(seg_rva));

        // Segment banner.
        push_row(&mut rows, &mut rva_index, Row::Seg(si), seg_rva);

        if seg_end <= seg_rva {
            continue;
        }

        // Walk the segment, alternating instruction runs and data gaps.
        let mut cursor = seg_rva;
        while cursor < seg_end {
            if let Some(&(ii, len)) = insn_at.get(&cursor) {
                // Function banner if a function starts exactly here.
                if let Some(&fi) = func_by_rva.get(&cursor) {
                    push_row(&mut rows, &mut rva_index, Row::Func(fi), cursor);
                }
                push_row(&mut rows, &mut rva_index, Row::Insn(ii), cursor);
                let next = cursor.saturating_add(len.max(1));
                cursor = next.min(seg_end).max(cursor.saturating_add(1));
                continue;
            }

            // No instruction at `cursor` — emit data rows up to the next
            // instruction within this segment (or the segment end).
            let next_insn = insn_at
                .range((cursor.saturating_add(1))..seg_end)
                .next()
                .map(|(&r, _)| r)
                .unwrap_or(seg_end);
            let gap_end = next_insn.min(seg_end);
            let mut d = cursor;
            while d < gap_end {
                let len = DATA_ROW.min(gap_end - d) as u32;
                if len == 0 {
                    break;
                }
                push_row(&mut rows, &mut rva_index, Row::Data { rva: d, len }, d);
                d = d.saturating_add(len as u64);
            }
            cursor = gap_end.max(cursor.saturating_add(1));
        }
    }

    let listing_len = rows.len();
    (rows, rva_index, listing_len)
}
