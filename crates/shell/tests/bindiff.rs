//! Two-binary function diffing: match functions across two binaries by their
//! recovered structure alone, then report exact / fuzzy / added / removed /
//! changed. A standalone reporting tool — it touches no decompiler hot path.
//!
//! The RVA is deliberately absent from every match key. The rva IS the identity
//! being recovered, so folding it into a key would make the self-diff a
//! tautology (every function trivially "matches" itself) instead of a real test
//! of the matcher. The only place ordering is consulted is as a tie-break among
//! candidates that are already provably indistinguishable.
//!
//! Tiers, cheapest first — a decompile costs ~1000x a histogram, so bodies are
//! only rendered for the handful of functions the structural tiers cannot call:
//!   A "exact"  — fnv1a(mnemonic histogram || blocks || calls), unique on both
//!                sides. No decompile.
//!   B "fuzzy"  — cosine over the mnemonic vector, ranked by call-graph
//!                neighbour agreement, iterated to a fixpoint so that evidence
//!                from settled matches propagates outward. No decompile.
//!   C "body"   — decompile the survivors, compare normalized body text.
//!
//! Run: cargo test --release -p disasmstudio --test bindiff -- --nocapture
//! Env: DS_DIFF_A, DS_DIFF_B  (binaries; B defaults to A, i.e. a self-diff)
//!      DS_DIFF_OUT           (report path, default <repo>/_qa/bindiff_report.txt)
//!      DS_DIFF_NOBODY        (skip tier C)
//!      DS_DIFF_CAP           (max functions per binary, default 4000)
//!      DS_DIFF_BODYCAP       (max tier-C decompiles per side, default 400)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use binparser::{Arch as PArch, BinaryMeta};
use bridge::{Arch as BArch, Engine, Func};

/* Fixed by the ABI (engine/include/disasm.h): DS_REF_CALL / DS_XREF_CALL == 1.
 * Compared as literals for the same reason lib.rs compares DS_REF_NONE to 0 —
 * it avoids depending on bindgen choosing to emit the enum constant. */
const REF_CALL: u8 = 1;
const XREF_CALL: u8 = 1;

/// A function shorter than this is structurally meaningless — a thunk, a stub,
/// a `xor eax,eax; ret`. Two unrelated binaries are *supposed* to share those,
/// so they are reported but excluded from the cross-binary assertion.
const TRIVIAL_INSNS: u32 = 8;

/// Structural similarity below this is never a match, whatever the call graph
/// says. Neighbour agreement ranks candidates; it cannot resurrect one.
const FUZZY_GATE: f64 = 0.75;

fn map_arch(a: PArch) -> BArch {
    match a {
        PArch::X86 => BArch::X86,
        PArch::X64 => BArch::X64,
        PArch::Arm => BArch::Arm,
        PArch::Arm64 => BArch::Arm64,
        PArch::Unknown => BArch::X64,
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn env_usize(k: &str, dflt: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(dflt)
}

/* ---- feature extraction -------------------------------------------------- */

struct FnFeat {
    rva: u64,
    name: String,
    insns: u32,
    blocks: u32,
    calls: u32,
    hist: BTreeMap<String, u32>,
    /// Cached L2 norm of `hist`, so the O(n*m) fuzzy sweep does not recompute it.
    norm: f64,
    key: u64,
    callees: Vec<u64>,
    callers: Vec<u64>,
}

impl FnFeat {
    fn trivial(&self) -> bool {
        self.insns < TRIVIAL_INSNS
    }
}

/// The Engine must outlive every feature derived from it (tier C calls back into
/// it to decompile), so it is owned alongside the features rather than dropped
/// at the end of a `load()` that only returned the features.
struct Loaded {
    engine: Engine,
    feats: Vec<FnFeat>,
    label: String,
}

/// Owning function of `rva`, by binary search over an rva-sorted slice. Mirrors
/// the `owner_of` lambda in decompiler.cpp:1272-1283, including its treatment of
/// a zero-size function as running to the next function's start.
fn owner_of(funcs: &[Func], rva: u64) -> Option<u64> {
    let lo = funcs.partition_point(|f| f.rva <= rva);
    if lo == 0 {
        return None;
    }
    let f = &funcs[lo - 1];
    let next = funcs.get(lo).map(|n| n.rva).unwrap_or(u64::MAX);
    if rva >= f.rva && (rva < f.rva + f.size || (f.size == 0 && rva < next)) {
        Some(f.rva)
    } else {
        None
    }
}

fn load(path: &str, label: &str, cap: usize) -> Option<Loaded> {
    if !std::path::Path::new(path).exists() {
        eprintln!("[skip] missing binary: {path}");
        return None;
    }
    let bytes = std::fs::read(path).expect("read");
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

    let mut funcs = engine.functions();
    funcs.sort_by_key(|f| f.rva);
    if funcs.len() > cap {
        funcs.truncate(cap);
    }

    /* One linear listing, sliced per function via index_for_rva. The obvious
     * `all.iter().filter(...)` per function (dump_pairs.rs:104) is O(funcs x
     * insns) — ~1497 funcs x ~180k insns is ~300M iterations per binary, twice
     * that for a diff. Walking forward from the function's own start index is
     * O(insns) total. */
    let total = engine.instruction_count();
    let all = engine.disasm_range(0, total);

    let mut feats = Vec::with_capacity(funcs.len());
    for f in &funcs {
        let end = f.rva + f.size.max(1);
        let mut hist: BTreeMap<String, u32> = BTreeMap::new();
        let mut callees: Vec<u64> = Vec::new();
        let mut insns = 0u32;
        let mut i = engine.index_for_rva(f.rva).unwrap_or(all.len());
        while i < all.len() && all[i].rva < end {
            let ins = &all[i];
            *hist.entry(ins.mnemonic.clone()).or_insert(0) += 1;
            insns += 1;
            if ins.ref_type == REF_CALL {
                if let Some(t) = ins.ref_target {
                    callees.push(t);
                }
            }
            i += 1;
        }

        /* There is no ds_xrefs_from in the ABI (disasm.h exposes only the _to
         * direction), so callees come from the instruction slice above and are
         * then lifted from call target to owning function here. */
        let mut callees: Vec<u64> = callees
            .iter()
            .filter_map(|&t| owner_of(&funcs, t))
            .filter(|&o| o != f.rva)
            .collect();
        callees.sort_unstable();
        callees.dedup();

        let mut callers: Vec<u64> = engine
            .xrefs_to(f.rva)
            .iter()
            .filter(|x| x.kind == XREF_CALL)
            .filter_map(|x| owner_of(&funcs, x.from_rva))
            .filter(|&o| o != f.rva)
            .collect();
        callers.sort_unstable();
        callers.dedup();

        let mut buf: Vec<u8> = Vec::with_capacity(hist.len() * 12 + 8);
        for (m, c) in &hist {
            buf.extend_from_slice(m.as_bytes());
            buf.push(0);
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&f.block_count.to_le_bytes());
        buf.extend_from_slice(&f.call_count.to_le_bytes());

        let norm = hist.values().map(|&c| (c as f64) * (c as f64)).sum::<f64>().sqrt();
        feats.push(FnFeat {
            rva: f.rva,
            name: f.name.clone(),
            insns,
            blocks: f.block_count,
            calls: f.call_count,
            key: fnv1a(&buf),
            hist,
            norm,
            callees,
            callers,
        });
    }
    Some(Loaded { engine, feats, label: label.to_string() })
}

/* ---- similarity ---------------------------------------------------------- */

/// Cosine over the sparse mnemonic vectors, by merge-walking two sorted maps.
fn cosine(a: &FnFeat, b: &FnFeat) -> f64 {
    if a.norm == 0.0 || b.norm == 0.0 {
        return 0.0;
    }
    let mut ia = a.hist.iter();
    let mut ib = b.hist.iter();
    let (mut ka, mut kb) = (ia.next(), ib.next());
    let mut dot = 0.0f64;
    while let (Some((ma, ca)), Some((mb, cb))) = (ka, kb) {
        match ma.cmp(mb) {
            std::cmp::Ordering::Equal => {
                dot += (*ca as f64) * (*cb as f64);
                ka = ia.next();
                kb = ib.next();
            }
            std::cmp::Ordering::Less => ka = ia.next(),
            std::cmp::Ordering::Greater => kb = ib.next(),
        }
    }
    dot / (a.norm * b.norm)
}

/// Fraction of `a`'s already-matched neighbours whose partner is a neighbour of
/// `b`. `None` when no neighbour has been matched yet — that is "no evidence",
/// which must not be conflated with "evidence of disagreement" (0.0).
fn neighbour_agreement(an: &[u64], bn: &[u64], a2b: &HashMap<u64, u64>) -> Option<f64> {
    let bset: HashSet<u64> = bn.iter().copied().collect();
    let (mut known, mut hit) = (0u32, 0u32);
    for n in an {
        if let Some(p) = a2b.get(n) {
            known += 1;
            if bset.contains(p) {
                hit += 1;
            }
        }
    }
    if known == 0 {
        None
    } else {
        Some(hit as f64 / known as f64)
    }
}

fn score(a: &FnFeat, b: &FnFeat, a2b: &HashMap<u64, u64>) -> Option<(f64, f64)> {
    let c = cosine(a, b);
    if c < FUZZY_GATE {
        return None;
    }
    let mut acc = Vec::new();
    if let Some(v) = neighbour_agreement(&a.callees, &b.callees, a2b) {
        acc.push(v);
    }
    if let Some(v) = neighbour_agreement(&a.callers, &b.callers, a2b) {
        acc.push(v);
    }
    let n = if acc.is_empty() {
        0.0
    } else {
        acc.iter().sum::<f64>() / acc.len() as f64
    };
    /* The gate above already decided this pair is admissible; the call graph
     * only ranks it. Letting a low `n` veto would strand identical duplicated
     * thunks whose neighbours happen to settle elsewhere. */
    Some((0.7 * c + 0.3 * n, c))
}

/* ---- body-text normalization (tier C) ------------------------------------ */

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// `fun_0006dcd0` -> FUN, `sub_1400012f0` -> SUB, and generically any
/// `<prefix>_<>=6 hex>` (flt_/dbl_/off_/loc_ data names) -> `<prefix>_A`. These
/// all bake an absolute address into the body text, which is exactly the layout
/// dependence the normalized hash exists to survive.
fn rewrite_ident(w: &str) -> Option<String> {
    if let Some(r) = w.strip_prefix("fun_") {
        if r.len() == 8 && r.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Some("FUN".into());
        }
    }
    if let Some(r) = w.strip_prefix("sub_") {
        if !r.is_empty() && r.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Some("SUB".into());
        }
    }
    let cut = w.rfind('_')?;
    let (pre, tail) = (&w[..cut], &w[cut + 1..]);
    if pre.is_empty() || tail.len() < 6 || !tail.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{pre}_A"))
}

fn rewrite_line(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut last_space = false;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            if !last_space && !out.is_empty() {
                out.push(' ');
                last_space = true;
            }
            i += 1;
            continue;
        }
        last_space = false;
        // Identifiers first: `fun_0006dcd0` must not be split by the hex rule.
        if is_ident_start(c) {
            let st = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            let w = &s[st..i];
            match rewrite_ident(w) {
                Some(r) => out.push_str(&r),
                None => out.push_str(w),
            }
            continue;
        }
        if c == b'0' && i + 1 < b.len() && (b[i + 1] | 32) == b'x' {
            let st = i;
            let hs = i + 2;
            let mut j = hs;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            /* Short constants (0x10, 0xff) are semantic — a struct offset, a
             * mask — so they stay. Only address-width literals are erased. */
            if j - hs >= 4 {
                out.push_str("IMM");
            } else {
                out.push_str(&s[st..j]);
            }
            i = j;
            continue;
        }
        if c.is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                out.push(b[i] as char);
                i += 1;
            }
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out.trim_end().to_string()
}

/// Strips everything the decompiler derives from *where* a function lives, so
/// what remains is what it *does*. Emit sites: decompiler.cpp:18961-18962 (the
/// `/* name @ 0xrva  size=n */` banner), :18963 (build_xref_comment, whose
/// caller list is derived data, not body semantics), :18969-18970 (the stdint
/// include).
///
/// DS_NO_XREFCOMMENT is deliberately *not* used to suppress the xref line: it is
/// latched into a function-local `static const bool` on first call
/// (decompiler.cpp:1270), so setting it mid-process is ineffective.
fn normalize_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("#include <stdint.h>") || t.starts_with("/* xrefs:") {
            continue;
        }
        if t.starts_with("/* ") && t.ends_with("*/") && t.contains(" @ 0x") && t.contains("size=") {
            continue;
        }
        let r = rewrite_line(t);
        if r.is_empty() {
            continue;
        }
        out.push_str(&r);
        out.push('\n');
    }
    out
}

/* ---- matching ------------------------------------------------------------ */

#[derive(Clone, Copy, PartialEq)]
enum Tier {
    Exact,
    Fuzzy,
    Body,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::Fuzzy => "fuzzy",
            Tier::Body => "body",
        }
    }
}

struct Match {
    a: usize,
    b: usize,
    tier: Tier,
    sim: f64,
    changed: bool,
}

fn diff(a: &Loaded, b: &Loaded, nobody: bool, bodycap: usize) -> Vec<Match> {
    let (fa, fb) = (&a.feats, &b.feats);
    let mut matches: Vec<Match> = Vec::new();
    let mut used_a = vec![false; fa.len()];
    let mut used_b = vec![false; fb.len()];
    // rva -> rva, the propagating evidence tier B feeds on.
    let mut a2b: HashMap<u64, u64> = HashMap::new();

    /* ---- tier A: a structural key unique on both sides is unambiguous ---- */
    let mut ka: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, f) in fa.iter().enumerate() {
        ka.entry(f.key).or_default().push(i);
    }
    let mut kb: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, f) in fb.iter().enumerate() {
        kb.entry(f.key).or_default().push(i);
    }
    for (k, va) in &ka {
        if va.len() != 1 {
            continue;
        }
        let Some(vb) = kb.get(k) else { continue };
        if vb.len() != 1 {
            continue;
        }
        let (i, j) = (va[0], vb[0]);
        used_a[i] = true;
        used_b[j] = true;
        a2b.insert(fa[i].rva, fb[j].rva);
        matches.push(Match { a: i, b: j, tier: Tier::Exact, sim: 1.0, changed: false });
    }

    /* ---- tier B: greedy on similarity, re-run so evidence propagates ----- */
    loop {
        let rem_a: Vec<usize> = (0..fa.len()).filter(|&i| !used_a[i]).collect();
        let rem_b: Vec<usize> = (0..fb.len()).filter(|&j| !used_b[j]).collect();
        if rem_a.is_empty() || rem_b.is_empty() {
            break;
        }
        let mut cands: Vec<(f64, f64, usize, usize)> = Vec::new();
        for &i in &rem_a {
            for &j in &rem_b {
                if let Some((s, c)) = score(&fa[i], &fb[j], &a2b) {
                    cands.push((s, c, i, j));
                }
            }
        }
        if cands.is_empty() {
            break;
        }
        /* Sort is total and rva-free except for the final index tie-break, which
         * only ever separates candidates that scored identically — i.e. ones the
         * evidence cannot distinguish. It buys determinism, not identity. */
        cands.sort_by(|x, y| {
            y.0.partial_cmp(&x.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(y.1.partial_cmp(&x.1).unwrap_or(std::cmp::Ordering::Equal))
                .then(x.2.cmp(&y.2))
                .then(x.3.cmp(&y.3))
        });
        let before = matches.len();
        for (s, c, i, j) in cands {
            if used_a[i] || used_b[j] {
                continue;
            }
            used_a[i] = true;
            used_b[j] = true;
            a2b.insert(fa[i].rva, fb[j].rva);
            matches.push(Match {
                a: i,
                b: j,
                tier: Tier::Fuzzy,
                sim: c,
                changed: fa[i].key != fb[j].key,
            });
            let _ = s;
        }
        if matches.len() == before {
            break;
        }
    }

    /* ---- tier C: only now, for survivors, is a decompile worth its cost --- */
    if !nobody {
        let rem_a: Vec<usize> = (0..fa.len()).filter(|&i| !used_a[i]).take(bodycap).collect();
        let rem_b: Vec<usize> = (0..fb.len()).filter(|&j| !used_b[j]).take(bodycap).collect();
        if !rem_a.is_empty() && !rem_b.is_empty() {
            let mut ha: HashMap<u64, Vec<usize>> = HashMap::new();
            for &i in &rem_a {
                let body = a.engine.decompile(fa[i].rva).unwrap_or_default();
                if body.trim().is_empty() {
                    continue;
                }
                ha.entry(fnv1a(normalize_body(&body).as_bytes())).or_default().push(i);
            }
            let mut hb: HashMap<u64, Vec<usize>> = HashMap::new();
            for &j in &rem_b {
                let body = b.engine.decompile(fb[j].rva).unwrap_or_default();
                if body.trim().is_empty() {
                    continue;
                }
                hb.entry(fnv1a(normalize_body(&body).as_bytes())).or_default().push(j);
            }
            for (h, va) in &ha {
                if va.len() != 1 {
                    continue;
                }
                let Some(vb) = hb.get(h) else { continue };
                if vb.len() != 1 {
                    continue;
                }
                let (i, j) = (va[0], vb[0]);
                if used_a[i] || used_b[j] {
                    continue;
                }
                used_a[i] = true;
                used_b[j] = true;
                matches.push(Match {
                    a: i,
                    b: j,
                    tier: Tier::Body,
                    sim: cosine(&fa[i], &fb[j]),
                    changed: fa[i].key != fb[j].key,
                });
            }
        }
    }
    matches
}

/* ---- report -------------------------------------------------------------- */

fn run(a_path: &str, b_path: &str, tag: &str) -> Option<(usize, usize, usize, usize)> {
    let cap = env_usize("DS_DIFF_CAP", 4000);
    let bodycap = env_usize("DS_DIFF_BODYCAP", 400);
    let nobody = std::env::var("DS_DIFF_NOBODY").is_ok();

    let t0 = std::time::Instant::now();
    let a = load(a_path, "A", cap)?;
    let b = load(b_path, "B", cap)?;
    let matches = diff(&a, &b, nobody, bodycap);
    let elapsed = t0.elapsed().as_millis();

    let mut in_a = vec![false; a.feats.len()];
    let mut in_b = vec![false; b.feats.len()];
    for m in &matches {
        in_a[m.a] = true;
        in_b[m.b] = true;
    }
    let n_exact = matches.iter().filter(|m| m.tier == Tier::Exact).count();
    let n_fuzzy = matches.iter().filter(|m| m.tier == Tier::Fuzzy).count();
    let n_body = matches.iter().filter(|m| m.tier == Tier::Body).count();
    let n_changed = matches.iter().filter(|m| m.changed).count();
    let removed: Vec<usize> = (0..a.feats.len()).filter(|&i| !in_a[i]).collect();
    let added: Vec<usize> = (0..b.feats.len()).filter(|&j| !in_b[j]).collect();

    // Trivial stubs match across unrelated binaries by construction; the honest
    // signal is what happened to the functions that actually have structure.
    let nt_a: Vec<usize> = (0..a.feats.len()).filter(|&i| !a.feats[i].trivial()).collect();
    let nt_matched = nt_a.iter().filter(|&&i| in_a[i]).count();
    let pct = |n: usize, d: usize| if d == 0 { 0.0 } else { 100.0 * n as f64 / d as f64 };

    let mut r = String::new();
    let _ = writeln!(r, "=== bindiff [{tag}] ===");
    let _ = writeln!(r, "A: {a_path}\n   {} functions", a.feats.len());
    let _ = writeln!(r, "B: {b_path}\n   {} functions", b.feats.len());
    let _ = writeln!(r, "elapsed: {elapsed} ms  (tier C {})", if nobody { "off" } else { "on" });
    let _ = writeln!(r, "---");
    let _ = writeln!(
        r,
        "matched : {} / {} A-funcs ({:.1}%)",
        matches.len(),
        a.feats.len(),
        pct(matches.len(), a.feats.len())
    );
    let _ = writeln!(r, "  exact : {n_exact}");
    let _ = writeln!(r, "  fuzzy : {n_fuzzy}");
    let _ = writeln!(r, "  body  : {n_body}");
    let _ = writeln!(r, "changed : {n_changed}  (matched, but structure differs)");
    let _ = writeln!(r, "removed : {}  (in A, not in B)", removed.len());
    let _ = writeln!(r, "added   : {}  (in B, not in A)", added.len());
    let _ = writeln!(
        r,
        "non-trivial (>= {TRIVIAL_INSNS} insns): {nt_matched} / {} matched ({:.1}%)",
        nt_a.len(),
        pct(nt_matched, nt_a.len())
    );
    let _ = writeln!(r, "---");

    let mut ms: Vec<&Match> = matches.iter().collect();
    ms.sort_by_key(|m| a.feats[m.a].rva);
    let _ = writeln!(r, "MATCHES (tier  simA  A -> B):");
    for m in ms.iter().take(2000) {
        let (x, y) = (&a.feats[m.a], &b.feats[m.b]);
        let _ = writeln!(
            r,
            "  {:<5} {:.3} {:#010x} {:<28} -> {:#010x} {:<28} [i{} b{} c{}]{}",
            m.tier.name(),
            m.sim,
            x.rva,
            x.name,
            y.rva,
            y.name,
            x.insns,
            x.blocks,
            x.calls,
            if m.changed { "  CHANGED" } else { "" }
        );
    }
    let _ = writeln!(r, "\nREMOVED (in A only):");
    for &i in removed.iter().take(500) {
        let f = &a.feats[i];
        let _ = writeln!(
            r,
            "  {:#010x} {:<28} [i{} b{} c{}]{}",
            f.rva,
            f.name,
            f.insns,
            f.blocks,
            f.calls,
            if f.trivial() { "  (trivial)" } else { "" }
        );
    }
    let _ = writeln!(r, "\nADDED (in B only):");
    for &j in added.iter().take(500) {
        let f = &b.feats[j];
        let _ = writeln!(
            r,
            "  {:#010x} {:<28} [i{} b{} c{}]{}",
            f.rva,
            f.name,
            f.insns,
            f.blocks,
            f.calls,
            if f.trivial() { "  (trivial)" } else { "" }
        );
    }

    let out = std::env::var("DS_DIFF_OUT").unwrap_or_else(|_| {
        // Resolved from the manifest, never hardcoded: a hardcoded absolute path
        // writes into the live repo no matter which checkout is running.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        root.join("_qa").join(format!("bindiff_{tag}.txt")).to_string_lossy().into_owned()
    });
    if let Some(d) = std::path::Path::new(&out).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&out, &r);

    // Summary to stdout; the per-function listing lives in the report file.
    for line in r.lines().take_while(|l| !l.starts_with("MATCHES")) {
        println!("{line}");
    }
    println!("[bindiff] report -> {out}");
    Some((matches.len(), a.feats.len(), nt_matched, nt_a.len()))
}

const NULLWARE: &str = r"C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll";

/// NullWare vs itself. Because no key contains an rva, 100% here is a real
/// statement about the matcher: it re-derived every identity from structure
/// alone. Anything under 100% is a bug or nondeterminism in the matcher.
#[test]
fn bindiff_self_is_total() {
    let a = std::env::var("DS_DIFF_A").unwrap_or_else(|_| NULLWARE.into());
    let Some((m, t, _, _)) = run(&a, &a, "self") else { return };
    assert_eq!(m, t, "self-diff must match every function: {m}/{t}");
}

/// NullWare vs an unrelated DLL. Not asserted at exactly 0: both are MSVC, so
/// they genuinely share trivial stubs, and calling those a false positive would
/// be dishonest. The claim under test is that nothing with real structure
/// matches across unrelated code.
#[test]
fn bindiff_unrelated_is_near_zero() {
    let a = std::env::var("DS_DIFF_A").unwrap_or_else(|_| NULLWARE.into());
    let b = std::env::var("DS_DIFF_B").unwrap_or_else(|_| {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        root.join("_qa").join("corpus").join("board.dll").to_string_lossy().into_owned()
    });
    let Some((_, _, ntm, ntt)) = run(&a, &b, "unrelated") else { return };
    let pct = if ntt == 0 { 0.0 } else { 100.0 * ntm as f64 / ntt as f64 };
    assert!(pct < 5.0, "unrelated binaries matched {ntm}/{ntt} non-trivial ({pct:.1}%)");
}
