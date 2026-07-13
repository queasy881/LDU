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
use std::sync::atomic::{AtomicBool, Ordering};
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
    pub engine: Option<Engine>,

    pub funcs: Vec<Func>,
    pub segs: Vec<Segment>,
    /// Export table: (rva, name), sorted by rva.
    pub exports: Vec<(u64, String)>,
    /// Import table: (IAT slot rva, name), sorted by name.
    pub imports: Vec<(u64, String)>,
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
    progress(&proxy, target, "Parsing binary", 0.0);

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
    progress(&proxy, target, "Parsing binary", 6.0);

    let parsed = match BinaryMeta::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            err_event(&proxy, target, format!("Parse error: {e}"));
            return;
        }
    };
    progress(&proxy, target, "Parsing binary", 12.0);

    let image = parsed.build_image(&bytes);
    let barch = map_arch(parsed.arch);
    let format = parsed.format;

    let mut engine = Engine::new(image, parsed.base, barch);
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

    // Retain the import/export tables for the sidebar (sorted for display).
    let mut exports: Vec<(u64, String)> = parsed
        .exports
        .iter()
        .map(|s| (s.rva, s.name.clone()))
        .collect();
    exports.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut imports: Vec<(u64, String)> = parsed
        .imports
        .iter()
        .map(|s| (s.rva, s.name.clone()))
        .collect();
    imports.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));

    progress(&proxy, target, "Parsing binary", 20.0);
    if is_cancelled(&cancel) {
        return;
    }

    // -- Stage 2: disassemble + build CFG (20..50) ---------------------------
    progress(&proxy, target, "Building CFG", 22.0);
    if let Err(e) = engine.disassemble() {
        err_event(&proxy, target, format!("Disassembly failed: {e}"));
        return;
    }
    if is_cancelled(&cancel) {
        return;
    }
    progress(&proxy, target, "Building CFG", 38.0);
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

    // -- Stage 5: build listing + rva index (90..99) -------------------------
    progress(&proxy, target, "Finalizing", 92.0);
    let meta = engine.meta();
    let snapshot = meta_snapshot(&format, &meta);
    let segs = engine.segments();
    let funcs = engine.functions();
    let (rows, rva_index, listing_len) = build_listing(&engine, &segs, &funcs);
    let strings = scan_strings(&engine, &segs);
    let data_xrefs = scan_pointers(&engine, &segs, meta.base, meta.image_size, meta.arch);
    progress(&proxy, target, "Finalizing", 99.0);
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
        s.engine = Some(engine);
        s.segs = segs;
        s.funcs = funcs;
        s.exports = exports;
        s.imports = imports;
        s.strings = strings;
        s.data_xrefs = data_xrefs;
        s.rows = rows;
        s.rva_index = rva_index;
        s.listing_len = listing_len;
    }

    push_event(&proxy, target, serde_json::json!({ "event": "analysis_done" }));
}

/// Scan mapped segments for printable strings: ASCII runs and UTF-16LE runs of
/// at least `MIN` chars. Returns (rva, value, kind) with kind 0=ascii, 1=utf16,
/// sorted by rva. Bounded so a huge image can't blow up memory.
fn scan_strings(engine: &Engine, segs: &[Segment]) -> Vec<(u64, String, u8)> {
    // min length 5 + null-termination (real C strings end in NUL) — this is what
    // keeps obfuscated/packed data sections from yielding thousands of random
    // printable-run false positives.
    const MIN: usize = 5;
    const MAX_VAL: usize = 240;
    const CAP: usize = 200_000;
    let printable = |b: u8| (0x20..=0x7e).contains(&b) || b == b'\t';

    let mut out: Vec<(u64, String, u8)> = Vec::new();
    'segs: for seg in segs {
        if seg.size == 0 {
            continue;
        }
        // Skip executable segments: code bytes (push/pop sequences, etc.)
        // produce enormous amounts of false-positive "strings". Real strings
        // live in data sections (.rdata / .data / .rsrc).
        if seg.flags & 4 != 0 {
            continue;
        }
        let bytes = engine.read_bytes(seg.rva, seg.size as usize);
        let n = bytes.len();
        if n == 0 {
            continue;
        }

        // ASCII runs.
        let mut i = 0usize;
        while i < n {
            if printable(bytes[i]) {
                let start = i;
                let mut j = i;
                while j < n && printable(bytes[j]) {
                    j += 1;
                }
                // Require NUL (or segment end) right after the run.
                let nul_terminated = j >= n || bytes[j] == 0;
                if j - start >= MIN && nul_terminated {
                    let take = (j - start).min(MAX_VAL);
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

        // UTF-16LE runs: [printable, 0x00] repeated.
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
                // Require a wide-NUL (low byte 0) or segment end after the run.
                let nul_terminated = j >= n || bytes[j] == 0;
                if s.len() >= MIN && nul_terminated {
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
    out.sort_by_key(|(rva, _, _)| *rva);
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
