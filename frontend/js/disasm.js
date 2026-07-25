/* ============================================================================
   disasm.js — SLATE IDE workspace controller.

   Layout: activity rail -> navigator panel -> assembly listing -> inspector.
   The inspector holds per-function tabs: Decompile · Graph · Offsets · Hex ·
   Xrefs. All per-function views (graph/offsets/hex) are derived CLIENT-SIDE by
   parsing the function's disassembly rows — no extra backend calls beyond the
   windowed get_disassembly the listing already uses.

   Uses window.DS (transport), window.U (dom + colorizers), window.VL (vlist),
   window.APP (palette/keymap). ref_type: 1 call, 2 jmp, 3 data, 4 branch.
   ============================================================================ */
(function () {
  "use strict";
  var U = window.U, DS = window.DS, VL = window.VL, APP = window.APP;
  var PAGE = 200, FN_ROW_CAP = 4000, ROWH = 26;

  var S = {
    meta: null,
    funcs: [], funcsSorted: [], imports: [], exports: [], strings: [], segs: [], problems: [],
    symByRva: new Map(), strByRva: new Map(), funcByRva: new Map(),
    listingLen: 0, vlist: null,
    cache: new Map(), reqPages: new Set(),
    funcRowsCache: new Map(),
    activeRva: null, curFn: null,
    panel: "functions", inspView: "decompile", graphDir: "callees",
    smOn: false, live: true, hlReg: null, topRva: null,
    booted: false, navSpan: null,
    navHist: [], navPos: -1, hlTok: null
  };

  /* ======================================================================
     BOOT / ANALYSIS
     ====================================================================== */
  APP.ready(function () {
    DS.invoke("get_session_info").then(function (i) {
      U.$("#ov-target").textContent = i ? (i.path || i.name || "") : "";
      var sb = U.$("#sb-name"); if (sb && i && i.name) sb.textContent = i.name;
      if (i && i.name) document.title = "DisasmStudio — " + i.name;
    }).catch(function () {});

    DS.on("analysis_progress", onProgress);
    DS.on("decompile_complete", function () {
      var hint = U.$("#sb-hint");
      if (hint) hint.textContent = "Ctrl F search · G goto · F5 decompile";
    });
    DS.on("analysis_error", onAnalysisError);
    DS.on("analysis_done", boot);

    wireChrome();
    registerCommands();

    // We may have loaded after analysis finished (missed the push): probe once.
    DS.invoke("get_binary_meta").then(boot).catch(function () { /* stay on overlay */ });
  });

  var ovSteps = [];   // ordered list of stage names seen, for the checklist
  function onProgress(p) {
    /* Once the window is up, decompilation continues in the BACKGROUND — the
       listing, xrefs, strings and navigation are all already usable. Report that
       in the status bar rather than the loading overlay, which is gone by then.
       (Previously the overlay stayed up for the whole decompile pass, so opening
       a large binary looked like a hang for minutes.) */
    if (S.booted) {
      var hint = U.$("#sb-hint");
      if (hint && p.total) {
        if (p.done >= p.total) {
          hint.textContent = "Ctrl F search · G goto · F5 decompile";
        } else {
          hint.textContent = "Decompiling " + p.done + " / " + p.total + " in background…";
        }
      }
      return;
    }
    var st = U.$("#ov-stage"), bar = U.$("#ov-bar"), pct = U.$("#ov-pct");
    if (p.stage && st) st.textContent = p.stage;
    // The percentage shown must MATCH what the user reads. For a counted stage
    // (decompiling N/total) that is the count fraction, not the overall bar value
    // — otherwise "569 / 1497" sat next to a mismatched 74.8%. Everything is
    // rounded to a whole number (no 74.82364729458918%).
    var frac;
    if (p.total) {
      frac = p.done / p.total;
      if (st) st.textContent = (p.stage || "Decompiling functions") + "  " + p.done + " / " + p.total;
    } else {
      frac = (p.pct || 0) / 100;
    }
    var v = Math.max(0, Math.min(100, Math.round(frac * 100)));
    if (bar) bar.style.width = v + "%";
    if (pct) pct.textContent = v + "%";
    if (p.stage) updateSteps(p.stage);
  }
  /* A running checklist of analysis stages (PE parse, imports/exports, disasm,
     CFG, symbols, xrefs, strings, decompile) so the whole pipeline is visible in
     one window. The current stage is active; earlier ones are ticked done. */
  function updateSteps(stage) {
    var base = stage.split("  ")[0];   // strip the " N / total" suffix so it stays one row
    if (ovSteps.length && ovSteps[ovSteps.length - 1].base === base) return;
    var host = U.$("#ov-steps"); if (!host) return;
    if (ovSteps.length) { var prev = ovSteps[ovSteps.length - 1]; prev.el.classList.remove("cur"); prev.el.classList.add("done"); }
    var li = U.el("li.ov-step.cur", {}, [U.el("span.ov-tick"), U.el("span.ov-step-name", { text: base })]);
    host.appendChild(li);
    ovSteps.push({ base: base, el: li });
  }
  function onAnalysisError(e) {
    U.$("#ov-running").hidden = true;
    var box = U.$("#ov-error"); box.hidden = false;
    U.$("#ov-error-msg").textContent = (e && e.message) || "unknown error";
  }

  function boot() {
    if (S.booted) return; S.booted = true;
    U.$("#overlay").classList.add("hide");

    Promise.all([
      DS.invoke("get_binary_meta").catch(function () { return null; }),
      DS.invoke("get_functions").catch(function () { return []; }),
      DS.invoke("get_imports").catch(function () { return []; }),
      DS.invoke("get_exports").catch(function () { return []; }),
      DS.invoke("get_strings").catch(function () { return []; }),
      DS.invoke("get_segments").catch(function () { return []; }),
      DS.invoke("get_listing_len").catch(function () { return { len: 0 }; }),
      DS.invoke("get_problems").catch(function () { return { count: 0, items: [] }; })
    ]).then(function (r) {
      S.meta = r[0] || {};
      S.funcs = r[1] || []; S.imports = r[2] || []; S.exports = r[3] || [];
      S.strings = r[4] || []; S.segs = r[5] || [];
      S.listingLen = (r[6] && r[6].len) || 0;
      S.problems = (r[7] && r[7].items) || [];
      updateProblemBadge();
      index();
      renderMeta();
      buildListing();
      renderPanel();
      drawJumpmap();
      var first = S.meta.entry != null ? S.meta.entry : (S.funcs[0] && S.funcs[0].rva);
      if (first != null) gotoRva(Number(first), true);
    });
  }

  function index() {
    S.symByRva.clear(); S.strByRva.clear(); S.funcByRva.clear();
    S.funcs.forEach(function (f) { S.symByRva.set(f.rva, f.name); S.funcByRva.set(f.rva, f); });
    S.exports.forEach(function (e) { if (!S.symByRva.has(e.rva)) S.symByRva.set(e.rva, e.name); });
    S.imports.forEach(function (i) { S.symByRva.set(i.rva, i.name); });
    S.importByRva = new Map(); S.imports.forEach(function (i) { S.importByRva.set(Number(i.rva), i.name); });
    S.strings.forEach(function (s) { S.strByRva.set(s.rva, s.value); });
    S.strRvasSorted = S.strings.map(function (s) { return { rva: Number(s.rva), value: s.value }; })
      .sort(function (a, b) { return a.rva - b.rva; });
    S.funcsSorted = S.funcs.slice().sort(function (a, b) { return a.rva - b.rva; });
    if (S.segs.length) {
      var lo = Infinity, hi = 0;
      S.segs.forEach(function (g) { lo = Math.min(lo, g.rva); hi = Math.max(hi, g.rva + g.size); });
      S.navSpan = { lo: lo, hi: hi };
    } else S.navSpan = null;
  }

  function renderMeta() {
    var m = S.meta, host = U.clear(U.$("#tb-meta"));
    function chip(k, v) { return U.el("span.meta-chip", { html: (k ? k + " " : "") + "<b>" + U.esc(v) + "</b>" }); }
    if (m.arch) host.appendChild(chip("", m.arch));
    if (m.base != null) host.appendChild(chip("base", U.hex(m.base)));
    if (m.function_count != null) host.appendChild(chip("", m.function_count + " fns"));
    if (m.instruction_count != null) host.appendChild(chip("", m.instruction_count + " insns"));
  }

  /* ======================================================================
     LISTING (windowed virtual list with a client page cache)
     ====================================================================== */
  function buildListing() {
    var host = U.$("#listing");
    if (S.vlist) S.vlist.destroy();
    S.vlist = VL.create(host, { rowHeight: ROWH, total: S.listingLen, overscan: 8, render: renderRow });
    host.addEventListener("scroll", U.debounce(onListScroll, 60), { passive: true });
    host.addEventListener("click", onListClick);
    host.addEventListener("mouseover", onListHover);
    host.addEventListener("mouseout", onListOut);
  }

  function pageOf(i) { return Math.floor(i / PAGE); }
  function ensurePage(i) {
    var pg = pageOf(i);
    if (S.reqPages.has(pg)) return;
    S.reqPages.add(pg);
    DS.invoke("get_disassembly", { start: pg * PAGE, count: PAGE }).then(function (rows) {
      rows = rows || [];
      for (var k = 0; k < rows.length; k++) S.cache.set(pg * PAGE + k, rows[k]);
      if (S.vlist) S.vlist.refresh();
    }).catch(function () { S.reqPages.delete(pg); });
  }

  function renderRow(index, slot) {
    var row = S.cache.get(index);
    if (!row) { ensurePage(index); slot.appendChild(U.el("div.ln", { html: '<span class="ln-addr">·</span>' })); return; }
    slot.appendChild(rowEl(row, index));
  }
  function rowEl(row, index) {
    if (row.kind === "func") return funcRow(row);
    if (row.kind === "segment") return segRow(row);
    if (row.kind === "data") return dataRow(row);
    return insnRow(row, index);
  }
  function isPad(row) {
    if (!row || row.kind !== "insn") return false;
    var m = (row.mnemonic || "").toLowerCase();
    return m === "int3" || (m === "int" && (row.operands || "").trim() === "3");
  }

  function funcRow(f) {
    return U.el("div.ln.func", { dataset: { rva: f.rva } }, [
      U.el("span.fn-badge", { text: "FUNC" }),
      U.el("span.fn-name", { text: f.name || ("sub_" + U.hex(f.rva).slice(2)) }),
      U.el("span.fn-meta", { text: U.hex(f.rva) + "  ·  " + (f.size || 0) + "b" + (f.block_count ? "  ·  " + f.block_count + " blk" : "") }),
      U.el("span.fn-xref", { text: "xrefs", onclick: function (e) { e.stopPropagation(); selectRva(f.rva); openXrefs(f.rva); } })
    ]);
  }
  function segRow(g) {
    return U.el("div.ln.seg", { dataset: { rva: g.rva } }, [
      U.el("span.ln-addr", { text: U.hex(g.rva) }),
      U.el("span.seg-name", { text: g.name }),
      U.el("span.seg-flags", { html: '<span class="' + (g.r ? "on" : "") + '">R</span><span class="' + (g.w ? "on" : "") + '">W</span><span class="' + (g.x ? "on" : "") + '">X</span>' }),
      U.el("span.fn-meta", { text: (g.size || 0) + " bytes" })
    ]);
  }
  function dataRow(d) {
    var str = stringInRange(Number(d.rva), d.len);
    var body = U.el("span.ln-body");
    if (str) {
      body.appendChild(U.el("span.d-str", { text: JSON.stringify(clip(str.value, 90)) }));
      body.appendChild(U.el("span.d-xref", { text: "XREFS →", title: "jump to the code that references this string",
        onclick: function (e) { e.stopPropagation(); jumpToStringXref(str.rva); } }));
    } else {
      body.appendChild(U.el("span.d-ascii", { text: d.ascii || "" }));
    }
    return U.el("div.ln.data" + (str ? ".is-str" : ""), { dataset: { rva: d.rva } }, [
      U.el("span.ln-addr", { text: U.hex(d.rva) }),
      U.el("span.ln-bytes", { text: d.bytes || "" }),
      body
    ]);
  }
  /* first string whose rva falls inside [rva, rva+len) */
  function stringInRange(rva, len) {
    var a = S.strRvasSorted; if (!a || !a.length) return null;
    var lo = 0, hi = a.length - 1;
    while (lo <= hi) { var mid = (lo + hi) >> 1; if (a[mid].rva < rva) lo = mid + 1; else hi = mid - 1; }
    var end = rva + (len || 1);
    return (lo < a.length && a[lo].rva >= rva && a[lo].rva < end) ? a[lo] : null;
  }
  /* from a string's DATA location, jump to the .text instruction referencing it
     (where the string is shown inline as a comment) + list all in the inspector. */
  function jumpToStringXref(strRva) {
    DS.invoke("get_xrefs_to", { rva: strRva }).then(function (xr) {
      xr = xr || [];
      openXrefs(strRva);
      if (xr.length) navigate(Number(xr[0].from_rva));
      else U.toast("no code references this string", "warn");
    }).catch(function () {});
  }
  function insnRow(ins, index) {
    var pad = isPad(ins), body = U.el("span.ln-body"), head = false;
    if (pad) {
      head = !isPad(S.cache.get(index - 1));
      if (head) {
        var n = 1; while (isPad(S.cache.get(index + n))) n++;
        body.innerHTML = '<span class="ln-mnem">' + U.esc(ins.mnemonic) + '</span>' +
          (n > 1 ? '<span class="pad-count">   × ' + n + ' padding</span>' : '');
      } else {
        body.innerHTML = '<span class="ln-mnem">' + U.esc(ins.mnemonic) + '</span>';
      }
    } else {
      body.innerHTML = '<span class="ln-mnem">' + U.esc(ins.mnemonic) + "</span>" +
        (ins.operands ? " " + U.colorOperands(ins.operands, ins.ref_type) : "");
      var ann = annotate(ins);
      if (ann) body.appendChild(ann);
      if (S.hlReg) markReg(body, S.hlReg);
    }
    var cls = "div.ln.insn" + (isFlow(ins.mnemonic) ? ".flow" : "") + (pad ? (head ? ".pad.pad-head" : ".pad") : "");
    var el = U.el(cls, { dataset: { rva: ins.rva, ref: ins.ref_target != null ? ins.ref_target : "" } }, [
      U.el("span.ln-addr", { text: U.hex(ins.rva) }),
      U.el("span.ln-bytes", { text: ins.bytes || "" }),
      body
    ]);
    if (S.activeRva != null && Number(ins.rva) === Number(S.activeRva)) el.classList.add("sel");
    return el;
  }

  function annotate(ins) {
    var t = ins.ref_target;
    if (t == null) return null;
    t = Number(t);
    if (ins.ref_type === 3 && S.strByRva.has(t)) {
      var wrap = U.el("span"); wrap.append("   ");
      wrap.appendChild(U.el("span.str-annot", { text: JSON.stringify(clip(S.strByRva.get(t), 48)),
        title: "jump to string @ " + U.hex(t),
        onclick: function (e) { e.stopPropagation(); navigate(t); } }));
      return wrap;
    }
    var name = S.symByRva.get(t);
    if (name) { var c = U.el("span.ref-cmt"); c.innerHTML = '   ; <span class="ref-sym">' + U.esc(name) + "</span>"; return c; }
    if (ins.ref_type === 1 || ins.ref_type === 2 || ins.ref_type === 4) {
      var c2 = U.el("span.ref-cmt"); c2.innerHTML = '   ; <span class="ref-sym">' + U.esc("loc_" + U.hex(t).slice(2)) + "</span>"; return c2;
    }
    return null;
  }
  function isFlow(m) { return /^(j|call|ret|loop|iret|syscall|int3?|ud2)/i.test(m || ""); }
  function clip(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) + "…" : s; }

  function onListScroll() {
    if (!S.vlist) return;
    var row = S.cache.get(S.vlist.topIndex());
    if (row && row.rva != null) { S.topRva = Number(row.rva); drawJumpmap(); }
  }
  function onListClick(e) {
    var tok = e.target.closest(".t-target");
    var ln = e.target.closest(".ln");
    if (tok && ln && ln.dataset.ref) { navigate(Number(ln.dataset.ref)); return; }
    if (ln && ln.dataset.rva) selectRva(Number(ln.dataset.rva));
  }

  /* ---- live register cross-highlight (hover) ----------------------------- */
  function onListHover(e) {
    var r = e.target.closest("[data-reg]");
    if (!r) return;
    var reg = r.getAttribute("data-reg");
    if (reg === S.hlReg) return;
    S.hlReg = reg; applyHl();
  }
  function onListOut(e) {
    if (e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest("[data-reg]")) return;
    if (!S.hlReg) return;
    S.hlReg = null; applyHl();
  }
  function applyHl() {
    var host = U.$("#listing");
    U.$all(".reg-hl", host).forEach(function (n) { n.classList.remove("reg-hl"); });
    if (S.hlReg) U.$all('[data-reg="' + cssEsc(S.hlReg) + '"]', host).forEach(function (n) { n.classList.add("reg-hl"); });
  }
  function markReg(scope, reg) { U.$all('[data-reg="' + cssEsc(reg) + '"]', scope).forEach(function (n) { n.classList.add("reg-hl"); }); }
  function cssEsc(s) { return String(s).replace(/["\\]/g, "\\$&"); }

  /* ======================================================================
     NAVIGATION
     ====================================================================== */
  /* ---- navigation history (back / forward) ------------------------------- */
  /* An rva jump stack so the ← → toolbar buttons walk where you've been, like
     IDA's Esc/Ctrl-arrow. Explicit jumps (navigate) push; back/forward replay
     without re-pushing. Scroll-driven selection does NOT push. */
  function pushNav(rva) {
    if (!isFinite(rva)) return;
    if (S.navHist[S.navPos] === rva) return;       // ignore a repeat of where we are
    S.navHist = S.navHist.slice(0, S.navPos + 1);   // drop any forward tail
    S.navHist.push(rva); S.navPos = S.navHist.length - 1;
    if (S.navHist.length > 200) { S.navHist.shift(); S.navPos--; }
    updateNavButtons();
  }
  function navBack() { if (S.navPos > 0) { S.navPos--; gotoRva(S.navHist[S.navPos], true); updateNavButtons(); } }
  function navForward() { if (S.navPos < S.navHist.length - 1) { S.navPos++; gotoRva(S.navHist[S.navPos], true); updateNavButtons(); } }
  function updateNavButtons() {
    var b = U.$("#tb-back"), f = U.$("#tb-fwd");
    if (b) b.disabled = S.navPos <= 0;
    if (f) f.disabled = S.navPos >= S.navHist.length - 1;
  }
  /* Ctrl+S: persist the decompilation so reopening this binary skips the
     decompile pass (the functions are already done). */
  function saveAnalysis() {
    U.toast("saving analysis…", "");
    DS.invoke("save_analysis").then(function (r) {
      if (r && r.ok) U.toast("saved " + (r.count || 0) + " functions — reopening won't re-analyze", "ok");
      else U.toast("save failed", "warn");
    }).catch(function () { U.toast("save failed", "warn"); });
  }
  function navigate(rva) { pushNav(Number(rva)); gotoRva(rva); }
  function gotoRva(rva, silent) {
    DS.invoke("get_row_for_rva", { rva: rva }).then(function (r) {
      var idx = r && r.index;
      if (idx == null || idx < 0) { if (!silent) U.toast("address not in listing", "warn"); return; }
      S.vlist.scrollTo(idx, "center");
      selectRva(rva);
      setTimeout(function () {
        var el = U.$('#listing .ln[data-rva="' + rva + '"]');
        if (el) { el.classList.add("flash"); setTimeout(function () { el.classList.remove("flash"); }, 1100); }
      }, 40);
    }).catch(function () {});
  }
  function selectRva(rva) {
    S.activeRva = Number(rva);
    syncPseudoToRva(S.activeRva);   /* Sync views: keep the pseudocode on this address */
    U.$all("#listing .ln.sel").forEach(function (n) { n.classList.remove("sel"); });
    var el = U.$('#listing .ln[data-rva="' + rva + '"]');
    if (el) el.classList.add("sel");
    var fn = funcAt(S.activeRva);
    var changed = fn && (!S.curFn || fn.rva !== S.curFn.rva);
    if (fn) S.curFn = fn;
    if (changed) onCurFnChanged();
    updateLoc(); updateStatus();
    if (S.live) {
      if (changed) refreshInspector();               // new function: re-render the view
      else if (S.inspView === "decompile") syncDecompCurrent(); // same function: just cross-highlight
    }
  }
  function updateStatus() {
    var r = U.$("#sb-rva"); if (r) r.textContent = S.activeRva != null ? U.hex(S.activeRva) : "—";
    var s = U.$("#sb-size"); if (s) s.textContent = S.curFn ? ("fn " + (S.curFn.size || 0) + " b") : "—";
  }
  function funcAt(rva) {
    var a = S.funcsSorted, lo = 0, hi = a.length - 1, best = null;
    while (lo <= hi) { var mid = (lo + hi) >> 1; if (a[mid].rva <= rva) { best = a[mid]; lo = mid + 1; } else hi = mid - 1; }
    if (!best) return null;
    if (best.size && rva >= best.rva + best.size) return best; // still nearest preceding
    return best;
  }
  function onCurFnChanged() { markNav(); drawJumpmap(); }
  function updateLoc() {
    var host = U.clear(U.$("#tb-loc"));
    if (S.curFn) {
      var off = S.activeRva != null ? Number(S.activeRva) - S.curFn.rva : 0;
      host.appendChild(U.el("span.loc-fn", { text: S.curFn.name || ("sub_" + U.hex(S.curFn.rva).slice(2)) }));
      host.appendChild(U.el("span.loc-off", { text: off > 0 ? "  +" + U.hex(off) : "  " + U.hex(S.curFn.rva) }));
    } else host.appendChild(U.el("span.loc-fn", { text: S.activeRva != null ? U.hex(S.activeRva) : "—" }));
  }

  /* ======================================================================
     NAVIGATOR PANEL
     ====================================================================== */
  function wirePanelActivity() {
    U.$all("#activity [data-panel]").forEach(function (b) {
      b.addEventListener("click", function () {
        U.$all("#activity [data-panel]").forEach(function (x) { x.classList.remove("on"); });
        b.classList.add("on"); S.panel = b.dataset.panel; renderPanel();
        U.$("#ide").classList.remove("panel-collapsed");
      });
    });
    var pt = U.$("#panel-toggle"); if (pt) pt.addEventListener("click", function () { U.$("#ide").classList.toggle("panel-collapsed"); });
    var it = U.$("#insp-toggle-top"); if (it) it.addEventListener("click", function () { U.$("#ide").classList.toggle("insp-collapsed"); });
    U.$("#panel-filter").addEventListener("input", U.debounce(renderPanel, 90));
  }
  function panelData() {
    switch (S.panel) {
      case "imports": return { title: "IMPORTS", grouped: true, items: S.imports.map(function (i) { return { rva: i.rva, name: i.name, sym: true, imp: true, dll: i.dll || "" }; }) };
      case "exports": return { title: "EXPORTS", items: S.exports.map(function (e) { return { rva: e.rva, name: e.name, sym: true }; }) };
      case "strings": return { title: "STRINGS", items: S.strings.map(function (s) { return { rva: s.rva, name: s.value, str: true }; }) };
      case "segments": return { title: "SEGMENTS", items: S.segs.map(function (g) { return { rva: g.rva, name: g.name, sub: (g.r ? "r" : "-") + (g.w ? "w" : "-") + (g.x ? "x" : "-") }; }) };
      /* Problems: every entry is a fact the analysis established (an indirect
         target it could not resolve, a function it recovered no block for), so
         clicking one navigates to the exact address it is about. */
      case "problems": return { title: "PROBLEMS", items: S.problems.map(function (p) {
        return { rva: p.rva, name: p.text, sub: p.func || "", prob: true }; }) };
      default: {
        var maxSz = 1;
        for (var k = 0; k < S.funcs.length; k++) { var s = S.funcs[k].size || 0; if (s > maxSz) maxSz = s; }
        return { title: "FUNCTIONS", fns: true, maxSz: maxSz, items: S.funcs.map(function (f) {
          return { rva: f.rva, name: f.name || ("sub_" + U.hex(f.rva).slice(2)),
                   named: !!f.name, size: f.size || 0, calls: f.call_count || 0, blocks: f.block_count || 0 }; }) };
      }
    }
  }
  function fnHumanSize(n) { return n >= 1024 ? (n / 1024).toFixed(n >= 10240 ? 0 : 1) + "K" : n + "b"; }
  function sortFns(items) {
    var s = S.fnSort || "addr";
    items.sort(function (a, b) {
      if (s === "name") { var an = a.named ? 0 : 1, bn = b.named ? 0 : 1; return an - bn || a.name.localeCompare(b.name); }
      if (s === "size") return (b.size - a.size) || (a.rva - b.rva);
      if (s === "calls") return (b.calls - a.calls) || (a.rva - b.rva);
      return a.rva - b.rva;   // addr
    });
    return items;
  }
  function ensureSortBar() {
    var bar = U.$("#panel-sort");
    if (bar) return bar;
    bar = U.el("div.panel-sort", { id: "panel-sort" });
    [["addr", "addr"], ["name", "name"], ["size", "size"], ["calls", "xrefs"]].forEach(function (o) {
      var b = U.el("button.sort-btn" + ((S.fnSort || "addr") === o[0] ? ".on" : ""), { dataset: { s: o[0] }, text: o[1] });
      b.addEventListener("click", function () {
        S.fnSort = o[0];
        U.$all("#panel-sort .sort-btn").forEach(function (x) { x.classList.toggle("on", x.dataset.s === o[0]); });
        renderPanel();
      });
      bar.appendChild(b);
    });
    var search = U.$(".panel-search");
    if (search && search.parentNode) search.parentNode.insertBefore(bar, search.nextSibling);
    return bar;
  }
  function renderPanel() {
    var d = panelData();
    var pt = U.$("#panel-title"); if (pt) pt.textContent = d.title;
    var q = (U.$("#panel-filter").value || "").toLowerCase();
    var items = (q ? d.items.filter(function (it) { return (it.name || "").toLowerCase().indexOf(q) >= 0 || U.hex(it.rva).indexOf(q) >= 0; }) : d.items).slice();
    // functions view: sort control + apply the chosen order
    var sortBar = U.$("#panel-sort");
    if (d.fns) { sortBar = ensureSortBar(); sortBar.hidden = false; sortFns(items); }
    else if (sortBar) { sortBar.hidden = true; }
    U.$("#panel-count").textContent = items.length + (q ? "/" + d.items.length : "");
    var host = U.clear(U.$("#panel-list"));
    var cap = 4000, n = Math.min(items.length, cap);
    var curDll = null, maxSz = d.maxSz || 1;
    for (var i = 0; i < n; i++) {
      (function (it) {
        // FUNCTIONS: a richer, scannable row — name (bold if named), a size bar
        // for visual weight, and a caller-count badge, so the list is browsable.
        if (d.fns) {
          var nm = U.el("span.nav-name.fn-nm" + (it.named ? ".fn-named" : ".fn-stub"), { text: it.name, title: it.name });
          var barW = Math.max(3, Math.min(100, Math.round(100 * (it.size / maxSz))));
          var bar = U.el("span.fn-bar", { title: it.size + " bytes · " + it.blocks + " blocks" }, [U.el("span.fn-bar-fill", { style: "width:" + barW + "%" })]);
          var mr = U.el("span.fn-mr", {}, [
            U.el("span.fn-sz", { text: fnHumanSize(it.size) }),
            it.calls ? U.el("span.fn-calls", { text: "↗" + it.calls, title: it.calls + " call sites" }) : U.el("span.fn-calls.z", { text: "" })
          ]);
          host.appendChild(U.el("button.nav-item.fn-row", { dataset: { rva: it.rva }, onclick: function () { navigate(Number(it.rva)); } }, [nm, bar, mr]));
          return;
        }
        // Imports get a per-DLL sub-header so they read as their own ".idata"
        // region instead of a flat list; items arrive already grouped by dll.
        if (d.grouped) {
          var dll = it.dll || "(unknown)";
          if (dll !== curDll) { curDll = dll; host.appendChild(U.el("div.nav-group", { text: dll })); }
        }
        var name = U.el("span.nav-name" + (it.sym ? ".sym" : it.str ? ".str" : ""), { text: it.str ? clip(it.name, 60) : it.name, title: it.name });
        var right = it.sub ? U.el("span.nav-sub", { text: it.sub }) : U.el("span.nav-addr", { text: U.hex(it.rva) });
        host.appendChild(U.el("button.nav-item" + (it.imp ? ".imp" : ""), { dataset: { rva: it.rva },
          onclick: it.imp ? function () { openImport(it); } : function () { navigate(Number(it.rva)); } }, [name, right]));
      })(items[i]);
    }
    if (items.length > cap) host.appendChild(U.el("div.view-empty", { text: "… " + (items.length - cap) + " more (filter to narrow)" }));
    markNav();
  }
  function markNav() {
    U.$all("#panel-list .nav-item.sel").forEach(function (n) { n.classList.remove("sel"); });
    var key = S.panel === "functions" && S.curFn ? S.curFn.rva : S.activeRva;
    if (key == null) return;
    var el = U.$('#panel-list .nav-item[data-rva="' + key + '"]');
    if (el) el.classList.add("sel");
  }

  /* ======================================================================
     INSPECTOR
     ====================================================================== */
  function wireInspector() {
    U.$all("#insp-tabs .insp-tab").forEach(function (t) { t.addEventListener("click", function () { setInspView(t.dataset.view); }); });
    U.$("#insp-toggle").addEventListener("click", function () { U.$("#ide").classList.toggle("insp-collapsed"); });
    U.$all("#sm-seg .seg-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        U.$all("#sm-seg .seg-btn").forEach(function (x) { x.classList.remove("on"); });
        b.classList.add("on"); S.smOn = b.dataset.sm === "1";
        if (S.curFn) decompile(S.curFn);
      });
    });
    U.$("#decomp-live").addEventListener("click", function () {
      S.live = !S.live; U.$("#decomp-live").classList.toggle("on", S.live);
      if (S.live && S.curFn) refreshInspector();
    });
    U.$("#decomp-copy").addEventListener("click", function () {
      U.copy(U.$("#decomp-code").textContent || "").then(function () { U.toast("copied", "ok"); });
    });
    U.$all("#graph-dir .seg-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        U.$all("#graph-dir .seg-btn").forEach(function (x) { x.classList.remove("on"); });
        b.classList.add("on"); S.graphDir = b.dataset.dir; if (S.curFn) renderGraph(S.curFn);
      });
    });
  }
  function setInspView(v) {
    S.inspView = v;
    U.$all("#insp-tabs .insp-tab").forEach(function (t) { t.classList.toggle("on", t.dataset.view === v); });
    U.$all(".insp-view").forEach(function (el) { el.classList.add("hide"); });
    U.$("#view-" + v).classList.remove("hide");
    U.$("#ide").classList.remove("insp-collapsed");
    refreshInspector();
  }
  function refreshInspector() {
    var f = S.curFn;
    U.$("#insp-sub").textContent = f ? (f.name || ("sub_" + U.hex(f.rva).slice(2))) + "   " + U.hex(f.rva) : "— no function selected —";
    if (!f) return;
    if (S.inspView === "decompile") decompile(f);
    else if (S.inspView === "graph") renderGraph(f);
    else if (S.inspView === "offsets") renderOffsets(f);
    else if (S.inspView === "hex") renderHex(f);
    else if (S.inspView === "xrefs") openXrefs(S.activeRva != null ? S.activeRva : f.rva, true);
    else if (S.inspView === "frame") renderFrame(f);
  }

  /* Scroll the pseudocode to the line covering `rva` and highlight it.
     decompile() already tagged each line with the addresses it came from
     (data-addrs, from the decompiler's own /*@addr*\/ markers), so this is a
     lookup, not a guess -- if no line claims the address, nothing moves rather
     than scrolling somewhere approximate. */
  function syncPseudoToRva(rva) {
    if (!S.syncViews || rva == null) return;
    var host = U.$("#decomp-code");
    if (!host) return;
    var want = Number(rva), hit = null;
    U.$all("#decomp-code .dc-line[data-addrs]").forEach(function (el) {
      if (hit) return;
      var list = el.dataset.addrs.split(",");
      for (var i = 0; i < list.length; i++) if (Number(list[i]) === want) { hit = el; return; }
    });
    if (!hit) return;
    U.$all("#decomp-code .dc-line.dc-sync").forEach(function (e) { e.classList.remove("dc-sync"); });
    hit.classList.add("dc-sync");
    var box = host.parentNode && host.parentNode.scrollHeight > host.parentNode.clientHeight
            ? host.parentNode : host;
    var top = hit.offsetTop - box.clientHeight / 2;
    box.scrollTop = top > 0 ? top : 0;
  }

  /* Problems badge on the activity rail. Hidden at zero rather than showing a
     "0" -- a permanent zero badge is chrome nobody reads, and the point of the
     count is that a non-zero one draws the eye. */
  function updateProblemBadge() {
    var b = U.$("#act-prob-badge");
    if (!b) return;
    var n = S.problems.length;
    b.textContent = n > 999 ? "999+" : String(n);
    b.classList.toggle("hide", n === 0);
    var tn = U.$("#tb-prob-n");
    if (tn) { tn.textContent = n ? " " + n : ""; tn.classList.toggle("warn", n > 0); }
    var btn = U.$('#activity [data-panel="problems"]');
    if (btn) btn.title = n === 0
      ? "Problems — none found"
      : n + " problem" + (n === 1 ? "" : "s") + " — unresolved indirect targets and un-analysed functions";
  }

  /* ---- stack frame ------------------------------------------------------- *
     The recovered frame of the selected function: offset, name, type, one row
     per slot. Served by get_stack_frame, which reads the SAME decompiler run
     the pseudocode comes from -- so this pane and the code beside it can never
     disagree about a variable's type.
     Negative offsets are locals below the frame pointer; the homed incoming
     arguments sit above it. Clicking a row filters the pseudocode to that name. */
  var frameSeq = 0;
  function renderFrame(f) {
    var host = U.$("#frame-host");
    host.textContent = "recovering frame for " + (f.name || U.hex(f.rva)) + " …";
    var seq = ++frameSeq;
    DS.invoke("get_stack_frame", { rva: f.rva }).then(function (res) {
      if (seq !== frameSeq) return;
      var slots = (res && res.slots) || [];
      host.innerHTML = "";
      if (!slots.length) {
        host.innerHTML = '<div class="frame-empty">no stack frame recovered ' +
                         '(register-only function, or no frame could be proven)</div>';
        return;
      }
      var head = document.createElement("div");
      head.className = "frame-row frame-head";
      head.innerHTML = '<span class="frame-off">Offset</span>' +
                       '<span class="frame-name">Name</span>' +
                       '<span class="frame-type">Type</span>';
      host.appendChild(head);
      slots.forEach(function (s) {
        var row = document.createElement("div");
        row.className = "frame-row";
        var isArg = s.off >= 0;
        if (isArg) row.classList.add("frame-arg");
        row.innerHTML = '<span class="frame-off">' + U.esc(s.off_text) + "</span>" +
                        '<span class="frame-name">' + U.esc(s.name) + "</span>" +
                        '<span class="frame-type">' + U.esc(s.type) + "</span>";
        row.title = (isArg ? "incoming argument" : "local") + " at frame " + s.off_text;
        row.addEventListener("click", function () {
          U.$all("#frame-host .frame-row").forEach(function (r) { r.classList.remove("sel"); });
          row.classList.add("sel");
        });
        host.appendChild(row);
      });
    }).catch(function (e) {
      if (seq !== frameSeq) return;
      host.innerHTML = '<div class="frame-empty">' + U.esc(String(e.message || e)) + "</div>";
    });
  }

  /* ---- decompile --------------------------------------------------------- */
  var decompSeq = 0;
  function decompile(f) {
    var code = U.$("#decomp-code"); code.textContent = "decompiling " + (f.name || U.hex(f.rva)) + " …";
    var seq = ++decompSeq, rva = f.rva;
    Promise.all([
      DS.invoke("get_pseudocode", { rva: rva, sm: S.smOn }),
      loadFuncRows(f)
    ]).then(function (res) {
      if (seq !== decompSeq) return;
      var src = (res[0] && res[0].code) || "/* (empty) */", rows = res[1] || [];
      // map ref targets -> the instruction that references them (for line sync)
      S.siteByTarget = new Map(); S.fnTargets = new Set();
      rows.forEach(function (ins) {
        if (ins.ref_target != null) { var t = Number(ins.ref_target); S.fnTargets.add(t); if (!S.siteByTarget.has(t)) S.siteByTarget.set(t, Number(ins.rva)); }
      });
      renderDecompile(src);
      var g = (src.match(/\bgoto\s+\w+;/g) || []).length;
      var meta = U.clear(U.$("#decomp-meta"));
      meta.appendChild(U.el("span", { text: src.split("\n").length + " lines" }));
      meta.appendChild(U.el("span" + (g ? ".dm-goto" : ""), { text: g + " goto" + (g === 1 ? "" : "s") }));
      if (S.smOn) meta.appendChild(U.el("span.dm-sm", { text: "state-machine" }));
      if (!S.smOn) setSmEnabled(g > 0);   // toggle only usable when a goto exists
      syncDecompCurrent();
    }).catch(function (e) {
      // HONEST error: show the engine's real reason (e.g. "no function at 0x… /
      // decompilation unavailable"), not a blank or fake-complete body.
      if (seq === decompSeq) {
        var msg = (e && e.message) ? e.message : "decompile failed";
        code.textContent = "/* " + msg + " */";
      }
    });
  }

  /* wrap each decompiled line, extracting the addresses it names so we can
     cross-highlight with the listing. */
  /* a few APIs read far better with decimal args (frequencies, durations) */
  function humanizeApis(s) {
    return s.replace(/\b(Beep)\s*\(\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*\)/g,
      function (_, fn, a, b) { return fn + "(" + parseInt(a, 16) + ", " + parseInt(b, 16) + ")"; });
  }
  var MARKER_RE = /\/\*@([0-9a-fA-F]+)\*\//g;
  function renderDecompile(src) {
    src = humanizeApis(src);
    var lines = src.split("\n"); S.dcAddrLines = new Map();
    var html = "";
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i], primary = null, marks = [], mm;
      MARKER_RE.lastIndex = 0;
      while ((mm = MARKER_RE.exec(raw))) marks.push(parseInt(mm[1], 16)); // statement addr(s) — a for() header may carry >1
      if (marks.length) { primary = marks[0]; raw = raw.replace(MARKER_RE, ""); }
      var addrs = extractAddrs(raw);              // + any call/jump/data targets the line names
      marks.forEach(function (a) { if (addrs.indexOf(a) < 0) addrs.unshift(a); });
      for (var k = 0; k < addrs.length; k++) { if (!S.dcAddrLines.has(addrs[k])) S.dcAddrLines.set(addrs[k], []); S.dcAddrLines.get(addrs[k]).push(i); }
      var attrs = ' data-line="' + i + '"' + (addrs.length ? ' data-addrs="' + addrs.join(",") + '"' : "") + (primary != null ? ' data-primary="' + primary + '"' : "");
      html += '<div class="dc-line"' + attrs + '>' + (U.colorC(raw) || "&#8203;") + "</div>";
    }
    U.$("#decomp-code").innerHTML = html;
  }
  function extractAddrs(line) {
    var out = [], m, seen = {};
    var reNamed = /\b(?:fun|sub|loc|j|off|byte|word|dword|qword|xmmword|ymmword|unk|flt|dbl|jpt|asc)_0*([0-9a-fA-F]+)\b/g;
    while ((m = reNamed.exec(line))) { var a = parseInt(m[1], 16); if (isFinite(a) && !seen[a]) { seen[a] = 1; out.push(a); } }
    var reHex = /0x([0-9a-fA-F]+)/g;
    while ((m = reHex.exec(line))) { var a2 = parseInt(m[1], 16); if (isFinite(a2) && !seen[a2] && (S.symByRva.has(a2) || S.funcByRva.has(a2) || S.strByRva.has(a2) || (S.fnTargets && S.fnTargets.has(a2)))) { seen[a2] = 1; out.push(a2); } }
    return out;
  }
  function setSmEnabled(on) {
    U.$all("#sm-seg .seg-btn").forEach(function (b) { b.disabled = !on; });
    U.$("#sm-seg").classList.toggle("disabled", !on);
  }
  function clearDcHl() { U.$all("#decomp-code .dc-hl").forEach(function (n) { n.classList.remove("dc-hl"); }); }
  /* highlight the decompile line(s) that reference the currently-selected instruction */
  function syncDecompCurrent() {
    clearDcHl();
    if (!S.dcAddrLines) return;
    var sel = U.$("#listing .ln.sel"); if (!sel) return;
    var rva = Number(sel.dataset.rva), ref = sel.dataset.ref ? Number(sel.dataset.ref) : null;
    var seen = {}, targets = [];
    if (S.dcAddrLines.has(rva)) targets.push(rva);
    if (ref != null && S.dcAddrLines.has(ref)) targets.push(ref);
    targets.forEach(function (t) {
      S.dcAddrLines.get(t).forEach(function (n) {
        if (seen[n]) return; seen[n] = 1;
        var el = U.$('#decomp-code .dc-line[data-line="' + n + '"]'); if (el) el.classList.add("dc-hl");
      });
    });
  }
  function onDecompClick(e) {
    if (window.getSelection && !window.getSelection().isCollapsed) return; // don't hijack text selection
    // Feature: click an identifier -> highlight every occurrence of it.
    var word = wordAtPoint(e.clientX, e.clientY);
    if (word) highlightToken(word); else highlightToken(null);
    var ln = e.target.closest(".dc-line"); if (!ln) return;
    var dest = ln.dataset.primary ? Number(ln.dataset.primary) : null; // the statement's own instruction
    if (dest == null && ln.dataset.addrs) {                             // fallback: a call/jump target it names
      var addrs = ln.dataset.addrs.split(",").map(Number);
      for (var i = 0; i < addrs.length; i++) { if (S.siteByTarget && S.siteByTarget.has(addrs[i])) { dest = S.siteByTarget.get(addrs[i]); break; } }
      if (dest == null) dest = addrs[0];
    }
    if (dest == null) return;
    ln.classList.add("dc-hl");
    navigate(Number(dest));
  }

  /* ---- click-to-highlight identifier occurrences ------------------------- */
  var TOK_SKIP = { "if": 1, "else": 1, "for": 1, "while": 1, "do": 1, "switch": 1, "case": 1, "default": 1,
    "return": 1, "goto": 1, "break": 1, "continue": 1, "sizeof": 1, "void": 1, "int": 1, "char": 1,
    "float": 1, "double": 1, "struct": 1, "const": 1, "unsigned": 1, "signed": 1, "static": 1 };
  /* the identifier under the pointer, or null (uses the caret API the webview supports) */
  function wordAtPoint(x, y) {
    var range = null;
    if (document.caretRangeFromPoint) range = document.caretRangeFromPoint(x, y);
    else if (document.caretPositionFromPoint) { var p = document.caretPositionFromPoint(x, y); if (p) { range = document.createRange(); range.setStart(p.offsetNode, p.offset); } }
    if (!range || !range.startContainer || range.startContainer.nodeType !== 3) return null;
    var t = range.startContainer.data, i = range.startOffset;
    var isw = function (c) { return c && /[A-Za-z0-9_]/.test(c); };
    if (!isw(t[i]) && !isw(t[i - 1])) return null;
    var a = i, b = i;
    while (a > 0 && isw(t[a - 1])) a--;
    while (b < t.length && isw(t[b])) b++;
    var w = t.slice(a, b);
    if (!w || /^[0-9]/.test(w) || TOK_SKIP[w] || w.length < 2) return null;
    return w;
  }
  function highlightToken(word) {
    var host = U.$("#decomp-code"); if (!host) return;
    // unwrap any previous highlight spans
    U.$all("#decomp-code .tok-hl").forEach(function (s) {
      var p = s.parentNode; if (!p) return; while (s.firstChild) p.insertBefore(s.firstChild, s); p.removeChild(s); p.normalize();
    });
    S.hlTok = word || null;
    if (!word) return;
    var re = new RegExp("(^|[^A-Za-z0-9_])(" + word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")(?![A-Za-z0-9_])");
    // walk text nodes, wrap exact-word matches
    var walker = document.createTreeWalker(host, NodeFilter.SHOW_TEXT, null), nodes = [], n;
    while ((n = walker.nextNode())) if (n.data.indexOf(word) >= 0) nodes.push(n);
    var count = 0;
    nodes.forEach(function (node) {
      var s = node.data, out = document.createDocumentFragment(), m, guard = 0;
      while ((m = re.exec(s)) && guard++ < 400) {
        var pre = m[1], hit = m[2], at = m.index + pre.length;
        if (at > 0) out.appendChild(document.createTextNode(s.slice(0, at)));
        var span = document.createElement("span"); span.className = "tok-hl"; span.textContent = hit; out.appendChild(span); count++;
        s = s.slice(at + hit.length);
      }
      if (count && s) out.appendChild(document.createTextNode(s));
      if (out.childNodes.length) node.parentNode.replaceChild(out, node);
    });
  }

  /* ---- hover preview for fun_/sub_ references ---------------------------- */
  var hovTip = null, hovRaf = 0;
  function ensureHovTip() { if (!hovTip) { hovTip = U.el("div", { id: "hovtip" }); document.body.appendChild(hovTip); } return hovTip; }
  function onDecompHover(e) {
    if (hovRaf) cancelAnimationFrame(hovRaf);
    hovRaf = requestAnimationFrame(function () {
      var w = wordAtPoint(e.clientX, e.clientY), rva = null;
      if (w) { var m = /^(?:fun|sub|loc|j)_0*([0-9a-fA-F]+)$/.exec(w); if (m) rva = parseInt(m[1], 16); }
      if (rva == null || !isFinite(rva)) { hideHovTip(); return; }
      var fn = S.funcByRva.get(rva) || funcAt(rva);
      var name = (fn && (fn.name || ("sub_" + U.hex(fn.rva).slice(2)))) || S.symByRva.get(rva) || ("loc_" + U.hex(rva).slice(2));
      var tip = ensureHovTip(); U.clear(tip);
      tip.appendChild(U.el("div.ht-name", { text: name }));
      var sub = U.el("div.ht-sub");
      sub.appendChild(U.el("span", {}, [U.el("span.ht-k", { text: "@ " }), document.createTextNode(U.hex(rva))]));
      if (fn && fn.size) sub.appendChild(U.el("span", {}, [document.createTextNode((fn.size) + " b")]));
      if (fn && fn.call_count != null) sub.appendChild(U.el("span", {}, [document.createTextNode(fn.call_count + " calls")]));
      tip.appendChild(sub);
      var px = Math.min(e.clientX + 14, window.innerWidth - 350), py = e.clientY + 18;
      tip.style.left = px + "px"; tip.style.top = py + "px"; tip.classList.add("show");
    });
  }
  function hideHovTip() { if (hovTip) hovTip.classList.remove("show"); }

  /* ---- load a function's instruction rows (client-side, cached) ---------- */
  function loadFuncRows(f) {
    if (S.funcRowsCache.has(f.rva)) return Promise.resolve(S.funcRowsCache.get(f.rva));
    return DS.invoke("get_row_for_rva", { rva: f.rva }).then(function (r) {
      var start = r && r.index; if (start == null || start < 0) return [];
      var want = Math.min(FN_ROW_CAP, Math.max(8, (f.size || 64)));
      return DS.invoke("get_disassembly", { start: start, count: want }).then(function (rows) {
        rows = rows || [];
        var end = f.rva + Math.max(1, f.size || 0), out = [];
        for (var i = 0; i < rows.length; i++) {
          var rw = rows[i];
          if (rw.kind === "func" && i > 0 && Number(rw.rva) !== f.rva) break;
          if (rw.kind === "segment" && i > 0) break;
          if (rw.rva != null && f.size && Number(rw.rva) >= end) break;
          if (rw.kind === "insn") out.push(rw);
        }
        S.funcRowsCache.set(f.rva, out);
        return out;
      });
    }).catch(function () { return []; });
  }

  /* ---- graph (expandable call TREE) -------------------------------------- */
  function fnName(rva) { return S.symByRva.get(rva) || ("fun_" + U.hex(rva).slice(2)); }
  function kindOf(rva) {
    if (S.importByRva && S.importByRva.has(rva)) return "api";   // external API
    if (S.funcByRva.has(rva)) return "fn";                        // internal function (expandable)
    return "unk";
  }
  /* unique call targets of an internal function, in first-seen order */
  function getCallees(rva) {
    var f = S.funcByRva.get(rva);
    if (!f) return Promise.resolve([]);
    return loadFuncRows(f).then(function (rows) {
      var seen = {}, out = [];
      rows.forEach(function (ins) {
        if (ins.ref_type === 1 && ins.ref_target != null) {
          var t = Number(ins.ref_target);
          if (seen[t]) return; seen[t] = 1;
          out.push({ rva: t, name: fnName(t), kind: kindOf(t) });
        }
      });
      return out;
    });
  }
  function treeNode(node, expandable) {
    var caret = U.el("button.tnode-caret", { text: expandable ? "▸" : "" });
    var glyph = node.kind === "api" ? "API" : node.kind === "self" ? "▣" : node.kind === "unk" ? "?" : "ƒ";
    var badge = U.el("span.tnode-badge." + node.kind, { text: glyph });
    var label = U.el("button.tnode-label" + (node.kind === "api" ? ".api" : ""), {
      text: clip(node.name, 42), title: node.name + "   " + U.hex(node.rva),
      onclick: function (e) { e.stopPropagation(); navigate(node.rva); }
    });
    var addr = U.el("span.tnode-addr", { text: U.hex(node.rva) });
    var row = U.el("div.tnode", { dataset: { rva: node.rva } }, [caret, badge, label, addr]);
    return { row: row, caret: caret };
  }
  function expandInto(container, rva, ancestors) {
    U.clear(container).appendChild(U.el("div.tnode-loading", { text: "…" }));
    getCallees(rva).then(function (callees) {
      U.clear(container);
      if (!callees.length) { container.appendChild(U.el("div.tnode-empty", { text: "leaf — no calls" })); return; }
      callees.forEach(function (c) {
        var rec = ancestors.indexOf(c.rva) >= 0;
        var expandable = c.kind === "fn" && !rec;
        var t = treeNode(c, expandable);
        if (rec) t.row.appendChild(U.el("span.tnode-rec", { text: "↻ recursive" }));
        container.appendChild(t.row);
        if (expandable) {
          var kids = U.el("div.tnode-children hide"), open = false, loaded = false;
          container.appendChild(kids);
          t.caret.addEventListener("click", function (e) {
            e.stopPropagation(); open = !open;
            t.caret.textContent = open ? "▾" : "▸";
            kids.classList.toggle("hide", !open);
            if (open && !loaded) { loaded = true; expandInto(kids, c.rva, ancestors.concat(c.rva)); }
          });
        }
      });
    });
  }
  /* ---- interactive spatial CALL GRAPH (nodes + curved edges, pan/zoom) -----
     Layered left→right (callees) / right→left (callers). Nodes are draggable
     into place by the layout; the canvas pans (drag) and zooms (wheel, toward
     the cursor). Hover a node to light up its subgraph; double-click (or the
     ⊕ pill) to grow its callees in place; click the label to navigate. */
  var NS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  var NODE_W = 176, NODE_H = 38, COL_GAP = 264, ROW_GAP = 20;

  function callersOf(rva) {
    return DS.invoke("get_xrefs_to", { rva: rva }).then(function (xr) {
      var seen = {}, out = [];
      (xr || []).forEach(function (x) {
        if (x.type !== 1) return;
        var fn = funcAt(Number(x.from_rva)), t = fn ? fn.rva : Number(x.from_rva);
        if (seen[t]) return; seen[t] = 1;
        out.push({ rva: t, name: (fn && fn.name) || fnName(t), kind: kindOf(t) });
      });
      return out;
    }).catch(function () { return []; });
  }

  function renderGraph(f) {
    var host = U.clear(U.$("#graph-host"));
    var callers = S.graphDir === "callers";
    var nodes = new Map(), edges = [];   // rva -> node ; {from,to}
    var edgeSet = new Set();
    function addNode(rva, name, kind) {
      var n = nodes.get(rva);
      if (!n) { n = { rva: rva, name: name, kind: kind, depth: 0, x: 0, y: 0, ex: 0, ey: 0, expanded: false, loading: false, kids: kind === "fn" || kind === "self" }; nodes.set(rva, n); }
      return n;
    }
    function addEdge(a, b) { var k = a + ">" + b; if (!edgeSet.has(k)) { edgeSet.add(k); edges.push({ from: a, to: b }); } }
    var root = addNode(f.rva, f.name || fnName(f.rva), "self");
    root.kids = true;

    var svg = svgEl("svg", { class: "cg-svg" });
    var defs = svgEl("defs");
    defs.innerHTML =
      '<marker id="cg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">' +
      '<path d="M0,0 L10,5 L0,10 z" class="cg-arrowhead"/></marker>';
    var vp = svgEl("g", { class: "cg-vp" });
    var gE = svgEl("g", { class: "cg-edges" }), gN = svgEl("g", { class: "cg-nodes" });
    vp.appendChild(gE); vp.appendChild(gN);
    svg.appendChild(defs); svg.appendChild(vp);
    host.appendChild(svg);

    var hud = U.el("div.cg-hud", {}, [
      U.el("button.cg-btn", { text: "⤢", title: "Fit to view", onclick: function () { fit(true); } }),
      U.el("button.cg-btn", { text: "−", title: "Zoom out", onclick: function () { zoomBy(1 / 1.25); } }),
      U.el("button.cg-btn", { text: "+", title: "Zoom in", onclick: function () { zoomBy(1.25); } })
    ]);
    host.appendChild(hud);
    var hint = U.el("div.cg-hint", { text: "drag to pan · scroll to zoom · double-click a node to expand" });
    host.appendChild(hint);

    var tx = 0, ty = 0, scale = 1;
    function apply() { vp.setAttribute("transform", "translate(" + tx.toFixed(2) + "," + ty.toFixed(2) + ") scale(" + scale.toFixed(4) + ")"); }
    function zoomBy(k) {
      var r = host.getBoundingClientRect(), cx = r.width / 2, cy = r.height / 2;
      var ns = Math.max(0.15, Math.min(2.6, scale * k));
      tx = cx - (cx - tx) * (ns / scale); ty = cy - (cy - ty) * (ns / scale); scale = ns; apply();
    }

    /* layered layout: BFS depth = column; within a column stack by insertion,
       then lift each column to center on the mean-y of its parents (tidy-ish). */
    function layout() {
      var byDepth = [];
      nodes.forEach(function (n) { (byDepth[n.depth] = byDepth[n.depth] || []).push(n); });
      var sign = callers ? -1 : 1;
      for (var d = 0; d < byDepth.length; d++) {
        var col = byDepth[d]; if (!col) continue;
        // order children under the average y of their parents to reduce crossings
        if (d > 0) col.sort(function (a, b) { return (parentMeanY(a) - parentMeanY(b)) || (a.rva - b.rva); });
        var totalH = col.length * NODE_H + (col.length - 1) * ROW_GAP;
        var y0 = -totalH / 2;
        for (var i = 0; i < col.length; i++) {
          col[i].ex = sign * d * COL_GAP;
          col[i].ey = y0 + i * (NODE_H + ROW_GAP);
        }
      }
      function parentMeanY(n) {
        var s = 0, c = 0;
        edges.forEach(function (e) { var tgt = callers ? e.from : e.to, src = callers ? e.to : e.from; if (tgt === n.rva) { var p = nodes.get(src); if (p) { s += p.ey; c++; } } });
        return c ? s / c : 0;
      }
    }

    function edgePath(a, b) {
      // from a's leading edge to b's trailing edge, horizontal-eased cubic
      var ax = callers ? a.x : a.x + NODE_W, ay = a.y + NODE_H / 2;
      var bx = callers ? b.x + NODE_W : b.x, by = b.y + NODE_H / 2;
      var mx = (ax + bx) / 2;
      return "M" + ax + "," + ay + " C" + mx + "," + ay + " " + mx + "," + by + " " + bx + "," + by;
    }

    function draw(animate) {
      layout(); commit();
      U.clear(gE); U.clear(gN);
      // adjacency for hover highlight
      var adj = new Map();
      edges.forEach(function (e) {
        (adj.get(e.from) || adj.set(e.from, new Set()).get(e.from)).add(e.to);
        (adj.get(e.to) || adj.set(e.to, new Set()).get(e.to)).add(e.from);
      });
      // edges
      var pathOf = {};
      edges.forEach(function (e) {
        var a = nodes.get(e.from), b = nodes.get(e.to); if (!a || !b) return;
        var p = svgEl("path", { class: "cg-edge", d: edgePath({ x: a.x, y: a.y }, { x: b.x, y: b.y }), "marker-end": "url(#cg-arrow)" });
        p.dataset.from = e.from; p.dataset.to = e.to;
        gE.appendChild(p); pathOf[e.from + ">" + e.to] = p;
      });
      // nodes
      nodes.forEach(function (n) {
        var g = svgEl("g", { class: "cg-node k-" + n.kind + ((S.curFn && n.rva === S.curFn.rva) ? " cur" : "") });
        g.dataset.rva = n.rva;
        g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
        var rect = svgEl("rect", { class: "cg-box", width: NODE_W, height: NODE_H, rx: 7 });
        var badge = svgEl("text", { class: "cg-badge", x: 13, y: NODE_H / 2 + 4 });
        badge.textContent = n.kind === "api" ? "API" : n.kind === "self" ? "◆" : n.kind === "unk" ? "?" : "ƒ";
        var nm = svgEl("text", { class: "cg-name", x: 34, y: 16 });
        nm.textContent = clip(n.name, 20);
        var addr = svgEl("text", { class: "cg-addr", x: 34, y: 29 });
        addr.textContent = U.hex(n.rva);
        var titleE = svgEl("title"); titleE.textContent = n.name + "  " + U.hex(n.rva);
        g.appendChild(rect); g.appendChild(badge); g.appendChild(nm); g.appendChild(addr); g.appendChild(titleE);
        if (n.kids && !n.expanded) {
          var pill = svgEl("g", { class: "cg-pill" });
          var px = callers ? -9 : NODE_W - 9;
          pill.appendChild(svgEl("circle", { cx: px, cy: NODE_H / 2, r: 9 }));
          var plus = svgEl("text", { x: px, y: NODE_H / 2 + 4, "text-anchor": "middle" }); plus.textContent = n.loading ? "…" : "+";
          pill.appendChild(plus);
          pill.addEventListener("click", function (ev) { ev.stopPropagation(); expand(n); });
          g.appendChild(pill);
        }
        // interactions
        g.addEventListener("mouseenter", function () { highlight(n.rva, adj); });
        g.addEventListener("mouseleave", function () { clearHi(); });
        g.addEventListener("click", function (ev) { if (dragMoved) return; navigate(n.rva); });
        g.addEventListener("dblclick", function (ev) { ev.stopPropagation(); if (n.kids) expand(n); });
        gN.appendChild(g);
        if (animate) {
          g.style.opacity = 0;
          g.setAttribute("transform", "translate(" + n.x + "," + n.y + ") scale(.9)");
          requestAnimationFrame(function () {
            g.style.transition = "opacity .28s ease, transform .34s cubic-bezier(.2,.9,.3,1)";
            g.style.opacity = ""; g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
          });
        }
      });
    }
    function highlight(rva, adj) {
      var near = adj.get(rva) || new Set(); near = new Set(near); near.add(rva);
      gN.querySelectorAll(".cg-node").forEach(function (g) { g.classList.toggle("dim", !near.has(+g.dataset.rva)); g.classList.toggle("hot", +g.dataset.rva === rva); });
      gE.querySelectorAll(".cg-edge").forEach(function (p) { var on = (+p.dataset.from === rva || +p.dataset.to === rva); p.classList.toggle("hot", on); p.classList.toggle("dim", !on); });
    }
    function clearHi() {
      gN.querySelectorAll(".cg-node").forEach(function (g) { g.classList.remove("dim", "hot"); });
      gE.querySelectorAll(".cg-edge").forEach(function (p) { p.classList.remove("dim", "hot"); });
    }

    function expand(n) {
      if (n.expanded || n.loading) return Promise.resolve();
      n.loading = true; draw(false);
      var p = callers ? callersOf(n.rva) : getCallees(n.rva);
      return p.then(function (kids) {
        n.loading = false; n.expanded = true;
        kids.forEach(function (c) {
          var cn = addNode(c.rva, c.name, c.kind);
          cn.depth = Math.max(cn.depth, n.depth + 1);
          if (callers) addEdge(c.rva, n.rva); else addEdge(n.rva, c.rva);
        });
        draw(true);
      });
    }

    function bounds() {
      var minx = 1e9, miny = 1e9, maxx = -1e9, maxy = -1e9;
      nodes.forEach(function (n) { minx = Math.min(minx, n.x); miny = Math.min(miny, n.y); maxx = Math.max(maxx, n.x + NODE_W); maxy = Math.max(maxy, n.y + NODE_H); });
      return { minx: minx, miny: miny, maxx: maxx, maxy: maxy };
    }
    function fit(anim) {
      var b = bounds(), r = host.getBoundingClientRect();
      var gw = Math.max(1, b.maxx - b.minx), gh = Math.max(1, b.maxy - b.miny), pad = 48;
      var ns = Math.min(1.4, Math.min((r.width - pad) / gw, (r.height - pad) / gh));
      ns = Math.max(0.15, ns || 1);
      var ntx = r.width / 2 - (b.minx + gw / 2) * ns, nty = r.height / 2 - (b.miny + gh / 2) * ns;
      if (anim) { vp.style.transition = "transform .4s cubic-bezier(.2,.9,.3,1)"; setTimeout(function () { vp.style.transition = ""; }, 420); }
      tx = ntx; ty = nty; scale = ns; apply();
    }

    // pan + zoom
    var dragging = false, dragMoved = false, sx = 0, sy = 0, stx = 0, sty = 0;
    svg.addEventListener("pointerdown", function (e) { dragging = true; dragMoved = false; sx = e.clientX; sy = e.clientY; stx = tx; sty = ty; svg.setPointerCapture(e.pointerId); svg.classList.add("cg-grab"); });
    svg.addEventListener("pointermove", function (e) { if (!dragging) return; var dx = e.clientX - sx, dy = e.clientY - sy; if (Math.abs(dx) + Math.abs(dy) > 3) dragMoved = true; tx = stx + dx; ty = sty + dy; apply(); });
    svg.addEventListener("pointerup", function (e) { dragging = false; svg.classList.remove("cg-grab"); });
    svg.addEventListener("wheel", function (e) {
      e.preventDefault();
      var r = host.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
      var k = e.deltaY < 0 ? 1.12 : 1 / 1.12, ns = Math.max(0.15, Math.min(2.6, scale * k));
      tx = mx - (mx - tx) * (ns / scale); ty = my - (my - ty) * (ns / scale); scale = ns; apply();
    }, { passive: false });

    // copy layout targets (ex/ey) into the live positions (x/y) used by render
    function commit() { nodes.forEach(function (n) { n.x = n.ex; n.y = n.ey; }); }

    expand(root).then(function () { fit(false); });
  }

  /* ---- offsets (reg+disp accesses = struct fields) ----------------------- */
  var REGW = (function () {
    var w = {};
    "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split(" ").forEach(function (r) { w[r] = 8; });
    "eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d".split(" ").forEach(function (r) { w[r] = 4; });
    "ax bx cx dx si di bp sp r8w r9w r10w r11w r12w r13w r14w r15w".split(" ").forEach(function (r) { w[r] = 2; });
    "al bl cl dl ah bh ch dh sil dil bpl spl r8b r9b r10b r11b r12b r13b r14b r15b".split(" ").forEach(function (r) { w[r] = 1; });
    return w;
  })();
  function inferWidth(ops) {
    var toks = ops.replace(/\[[^\]]*\]/g, " ").match(/\b([a-z][a-z0-9]+)\b/g) || [];
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (REGW[t]) return REGW[t];
      if (/^xmm\d+$/.test(t)) return 16;
      if (/^ymm\d+$/.test(t)) return 32;
    }
    return 0;
  }
  function widthType(w) { return { 1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t", 16: "__m128", 32: "__m256" }[w] || "–"; }
  function accessMode(mnem, memIsDest) {
    if (mnem === "cmp" || mnem === "test" || mnem === "push") return "r";
    if (mnem === "pop") return "w";
    if (/^mov/.test(mnem)) return memIsDest ? "w" : "r";
    if (/^(add|sub|and|or|xor|inc|dec|adc|sbb|neg|not|shl|shr|sar|sal|rol|ror|xadd|xchg|cmpxchg|btc|bts|btr)$/.test(mnem)) return memIsDest ? "rw" : "r";
    return "r";
  }
  function renderOffsets(f) {
    var host = U.clear(U.$("#offsets-host"));
    host.appendChild(U.el("div.view-empty", { text: "scanning accesses…" }));
    loadFuncRows(f).then(function (rows) {
      var map = new Map();
      // [base (+ index*scale)? +/- disp]
      var memRe = /\[\s*([a-z][a-z0-9]*)\s*(?:\+\s*[a-z][a-z0-9]*\s*\*\s*\d\s*)?([+\-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]/gi;
      var sizeKw = { byte: 1, word: 2, dword: 4, qword: 8, xmmword: 16, ymmword: 32 };
      rows.forEach(function (ins) {
        var mnem = (ins.mnemonic || "").toLowerCase();
        if (mnem === "lea" || mnem === "nop") return; // lea computes an address, not a dereference
        var ops = ins.operands || "", m;
        var explicit = (/\b(byte|word|dword|qword|xmmword|ymmword)\b/i.exec(ops) || [])[1];
        var width = explicit ? sizeKw[explicit.toLowerCase()] : inferWidth(ops);
        var comma = ops.indexOf(",");
        memRe.lastIndex = 0;
        while ((m = memRe.exec(ops))) {
          var reg = m[1].toLowerCase();
          if (reg === "rip" || reg === "eip") continue;                 // rip-relative = global, not a struct field
          var num = parseInt(m[3], /^0x/i.test(m[3]) ? 16 : 10);
          var disp = (m[2] === "-" ? -num : num);
          if (disp === 0) continue;
          if (Math.abs(disp) >= 0x10000) continue;                      // implausibly large for a struct field
          var memIsDest = comma < 0 ? true : m.index < comma;
          var mode = accessMode(mnem, memIsDest);
          var key = reg + "|" + disp, rec = map.get(key);
          if (!rec) { rec = { reg: reg, disp: disp, count: 0, first: ins.rva, width: 0, read: false, write: false }; map.set(key, rec); }
          rec.count++;
          if (!rec.width && width) rec.width = width;
          if (mode.indexOf("r") >= 0) rec.read = true;
          if (mode.indexOf("w") >= 0) rec.write = true;
        }
      });
      var arr = Array.from(map.values()).sort(function (a, b) { return a.reg === b.reg ? a.disp - b.disp : (a.reg < b.reg ? -1 : 1); });
      host = U.clear(U.$("#offsets-host"));
      if (!arr.length) { host.appendChild(U.el("div.view-empty", { text: "No [reg+disp] accesses recorded for this function." })); return; }
      host.appendChild(U.el("div.off-row.head", null, [
        U.el("span", { text: "ACCESS" }), U.el("span", { text: "TYPE" }), U.el("span", { text: "R/W" }),
        U.el("span", { text: "HITS" }), U.el("span", { text: "FIRST @", style: "text-align:right" })
      ]));
      arr.forEach(function (r) {
        var disp = (r.disp < 0 ? "-0x" + (-r.disp).toString(16) : "+0x" + r.disp.toString(16));
        var rw = r.read && r.write ? "R/W" : r.write ? "W" : "R";
        var rwCls = r.read && r.write ? "rw" : r.write ? "w" : "r";
        host.appendChild(U.el("div.off-row", null, [
          U.el("span.off-acc", { html: "[" + U.esc(r.reg) + "<b>" + disp + "</b>]" }),
          U.el("span.off-type", { text: widthType(r.width) }),
          U.el("span.off-mode." + rwCls, { text: rw }),
          U.el("span.off-hits", { text: r.count + "×" }),
          U.el("span.off-first", { text: U.hex(r.first) + " ↗", title: "go to first access", onclick: function () { navigate(Number(r.first)); } })
        ]));
      });
    });
  }

  /* ---- hex (per-function dump) ------------------------------------------- */
  function renderHex(f) {
    var head = U.$("#hex-head"), host = U.clear(U.$("#hex-host"));
    host.appendChild(U.el("div.view-empty", { text: "reading bytes…" }));
    loadFuncRows(f).then(function (rows) {
      var bytes = [], baseRva = null;
      rows.forEach(function (ins) {
        if (baseRva == null) baseRva = Number(ins.rva);
        (ins.bytes || "").trim().split(/\s+/).forEach(function (h) { if (h) bytes.push(parseInt(h, 16)); });
      });
      if (baseRva == null) baseRva = f.rva;
      var seg = segOf(f.rva);
      head.innerHTML = "section <b>" + U.esc(seg ? seg.name : "?") + "</b>  ·  va <b>" + U.hex(baseRva) + "</b>  ·  length <b>0x" + bytes.length.toString(16) + "</b>";
      host = U.clear(U.$("#hex-host"));
      for (var off = 0; off < bytes.length; off += 16) {
        var slice = bytes.slice(off, off + 16);
        var hexs = slice.map(function (b) { return '<span class="' + (b === 0 ? "z" : "") + '">' + (b < 16 ? "0" : "") + b.toString(16) + "</span>"; }).join(" ");
        var asc = slice.map(function (b) { return (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : "."; }).join("");
        host.appendChild(U.el("div.hx", null, [
          U.el("span.hx-addr", { text: U.hex(baseRva + off) }),
          U.el("span.hx-bytes", { html: hexs }),
          U.el("span.hx-ascii", { text: asc })
        ]));
      }
      if (!bytes.length) host.appendChild(U.el("div.view-empty", { text: "No bytes available." }));
    });
  }
  function segOf(rva) { for (var i = 0; i < S.segs.length; i++) { var g = S.segs[i]; if (rva >= g.rva && rva < g.rva + g.size) return g; } return null; }

  /* ---- imports ----------------------------------------------------------- */
  /* An import is not code you can jump into — its rva is an IAT slot in .rdata.
     Jumping there dumps the user among rodata strings. Instead, present the
     import as its own thing: name + owning DLL, then its call sites (xrefs to
     the IAT slot), each of which DOES jump into real code. */
  function openImport(it) {
    var rva = Number(it.rva);
    S.activeRva = rva; markNav();
    setInspView("xrefs");
    var host = U.clear(U.$("#xrefs-host"));
    host.appendChild(U.el("div.import-card", {}, [
      U.el("span.import-name", { text: it.name, title: it.name }),
      U.el("span.import-dll", { text: it.dll || "import" }),
      U.el("span.import-slot", { text: "IAT " + U.hex(rva) })
    ]));
    var body = U.el("div.import-refs"); host.appendChild(body);
    body.appendChild(U.el("div.view-empty", { text: "resolving call sites …" }));
    DS.invoke("get_xrefs_to", { rva: rva }).then(function (xr) {
      xr = xr || []; U.clear(body);
      body.appendChild(U.el("div.xref-group", { text: xr.length + " CALL SITE" + (xr.length === 1 ? "" : "S") }));
      if (!xr.length) { body.appendChild(U.el("div.view-empty", { text: "No direct references (may be called indirectly)." })); return; }
      xr.forEach(function (x) {
        var kind = x.type === 1 ? "call" : x.type === 2 ? "jump" : x.type === 3 ? "data" : "ref";
        var fn = funcAt(Number(x.from_rva));
        body.appendChild(U.el("button.xref-item", { onclick: function () { navigate(Number(x.from_rva)); } }, [
          U.el("span.xr-kind." + kind, { text: kind }),
          U.el("span.xr-from", { text: U.hex(x.from_rva) }),
          U.el("span.xr-ctx", { text: fn ? "in " + (fn.name || ("sub_" + U.hex(fn.rva).slice(2))) : "" })
        ]));
      });
    }).catch(function () {});
  }

  /* ---- xrefs ------------------------------------------------------------- */
  function openXrefs(rva, keepView) {
    if (!keepView) setInspView("xrefs");
    var host = U.clear(U.$("#xrefs-host"));
    host.appendChild(U.el("div.view-empty", { text: "resolving xrefs to " + U.hex(rva) + " …" }));
    DS.invoke("get_xrefs_to", { rva: rva }).then(function (xr) {
      xr = xr || []; host = U.clear(U.$("#xrefs-host"));
      host.appendChild(U.el("div.xref-group", { text: xr.length + " REFERENCE" + (xr.length === 1 ? "" : "S") + " TO " + U.hex(rva) }));
      if (!xr.length) { host.appendChild(U.el("div.view-empty", { text: "No cross-references." })); return; }
      xr.forEach(function (x) {
        var kind = x.type === 1 ? "call" : x.type === 2 ? "jump" : x.type === 3 ? "data" : "ref";
        var fn = funcAt(Number(x.from_rva));
        host.appendChild(U.el("button.xref-item", { onclick: function () { navigate(Number(x.from_rva)); } }, [
          U.el("span.xr-kind." + kind, { text: kind }),
          U.el("span.xr-from", { text: U.hex(x.from_rva) }),
          U.el("span.xr-ctx", { text: fn ? "in " + (fn.name || ("sub_" + U.hex(fn.rva).slice(2))) : "" })
        ]));
      });
    }).catch(function () {});
  }

  /* ======================================================================
     JUMP MAP
     ====================================================================== */
  function drawJumpmap() {
    var cv = U.$("#jumpmap"); if (!cv || !S.navSpan) return;
    var w = cv.clientWidth || 12, h = cv.clientHeight || (cv.parentElement && cv.parentElement.clientHeight) || 600;
    cv.width = w; cv.height = h;
    var ctx = cv.getContext("2d"); if (!ctx) return;
    ctx.clearRect(0, 0, w, h);
    var lo = S.navSpan.lo, span = Math.max(1, S.navSpan.hi - S.navSpan.lo);
    function y(rva) { return Math.round((Number(rva) - lo) / span * h); }
    S.segs.forEach(function (g) {
      var y0 = y(g.rva), y1 = y(g.rva + g.size);
      ctx.fillStyle = g.x ? "rgba(0,0,0,.16)" : g.w ? "rgba(0,0,0,.09)" : "rgba(0,0,0,.05)";
      ctx.fillRect(0, y0, w, Math.max(1, y1 - y0));
    });
    ctx.fillStyle = "rgba(0,0,0,.24)";
    S.funcsSorted.forEach(function (f) { ctx.fillRect(0, y(f.rva), w, 1); });
    if (S.curFn) { ctx.fillStyle = "rgba(0,0,0,.9)"; ctx.fillRect(0, y(S.curFn.rva) - 1, w, 3); }
    if (S.topRva != null) { ctx.strokeStyle = "rgba(0,0,0,.55)"; ctx.strokeRect(1, y(S.topRva), w - 2, Math.max(6, h * 0.04)); }
  }
  function wireJumpmap() {
    var cv = U.$("#jumpmap");
    cv.addEventListener("click", function (e) {
      if (!S.navSpan) return;
      var rect = cv.getBoundingClientRect();
      var frac = (e.clientY - rect.top) / rect.height;
      var rva = Math.round(S.navSpan.lo + frac * (S.navSpan.hi - S.navSpan.lo));
      var f = null; for (var i = 0; i < S.funcsSorted.length; i++) { if (S.funcsSorted[i].rva >= rva) { f = S.funcsSorted[i]; break; } }
      navigate(f ? f.rva : rva);
    });
  }

  /* ---- resizable panels + font size (persisted layout) ------------------- */
  function wireResizers() {
    var specs = [
      { h: "#rz-panel", el: "#panel", vr: "--panel-w", dir: 1, min: 150, max: 640 },
      { h: "#rz-insp",  el: "#inspector", vr: "--insp-w", dir: -1, min: 240, max: 860 }
    ];
    specs.forEach(function (sp) {
      var handle = U.$(sp.h); if (!handle) return;
      handle.addEventListener("mousedown", function (e) {
        e.preventDefault();
        var ide = U.$("#ide"); ide.classList.add("rz-drag"); handle.classList.add("on");
        var startX = e.clientX, startW = U.$(sp.el).getBoundingClientRect().width;
        function mv(ev) {
          var w = Math.max(sp.min, Math.min(sp.max, startW + (ev.clientX - startX) * sp.dir));
          document.documentElement.style.setProperty(sp.vr, w + "px");
        }
        function up() {
          document.removeEventListener("mousemove", mv); document.removeEventListener("mouseup", up);
          ide.classList.remove("rz-drag"); handle.classList.remove("on"); drawJumpmap();
          try { localStorage.setItem("ds" + sp.vr, document.documentElement.style.getPropertyValue(sp.vr)); } catch (_) {}
        }
        document.addEventListener("mousemove", mv); document.addEventListener("mouseup", up);
      });
    });
  }
  function applyFont(px) {
    px = Math.max(10, Math.min(20, px)); S.dcFs = px;
    document.documentElement.style.setProperty("--dc-fs", px + "px");
    try { localStorage.setItem("dsDcFs", String(px)); } catch (_) {}
  }
  function restoreLayout() {
    try {
      var pw = localStorage.getItem("ds--panel-w"); if (pw) document.documentElement.style.setProperty("--panel-w", pw);
      var iw = localStorage.getItem("ds--insp-w"); if (iw) document.documentElement.style.setProperty("--insp-w", iw);
      var fs = parseInt(localStorage.getItem("dsDcFs"), 10); if (isFinite(fs)) applyFont(fs);
    } catch (_) {}
  }

  /* ======================================================================
     CHROME
     ====================================================================== */
  function wireChrome() {
    wirePanelActivity();
    wireInspector();
    wireJumpmap();

    U.$("#tb-goto").addEventListener("click", openGoto);
    U.$("#tb-decompile").addEventListener("click", function () { setInspView("decompile"); if (S.curFn) decompile(S.curFn); });
    U.$("#tb-cmd").addEventListener("click", function () { APP.palette.open(); });
    U.$("#tb-back").addEventListener("click", navBack);
    U.$("#tb-fwd").addEventListener("click", navForward);
    updateNavButtons();
    U.$("#ov-cancel").addEventListener("click", function () { DS.invoke("cancel_analysis").catch(function () {}); });
    U.$("#ov-retry").addEventListener("click", function () { location.reload(); });

    U.$("#goto-form").addEventListener("submit", function (e) { e.preventDefault(); commitGoto(); });
    var dc = U.$("#decomp-code");
    dc.addEventListener("click", onDecompClick);
    dc.addEventListener("mousemove", onDecompHover);
    dc.addEventListener("mouseleave", hideHovTip);

    // font-size controls for the decompile pane (persisted)
    var fi = U.$("#dc-finc"), fd = U.$("#dc-fdec");
    if (fi) fi.addEventListener("click", function () { applyFont((S.dcFs || 13) + 1); });
    if (fd) fd.addEventListener("click", function () { applyFont((S.dcFs || 13) - 1); });

    /* Hexstrand action strip. Each button does a real thing; a control that
       only looked like a button would be worse than not having it. */
    var bx = U.$("#tb-xrefs");
    if (bx) bx.addEventListener("click", function () {
      var r = S.activeRva != null ? S.activeRva : (S.curFn && S.curFn.rva);
      if (r != null) { setInspView("xrefs"); openXrefs(r, true); }
    });
    var bs = U.$("#tb-strings");
    if (bs) bs.addEventListener("click", function () { pickPanel("strings"); });
    var bp = U.$("#tb-problems");
    if (bp) bp.addEventListener("click", function () { pickPanel("problems"); });
    /* Sync views: when on, selecting an instruction scrolls the pseudocode to the
       line that carries that address (the decompiler emits `/*@addr*\/` markers,
       which decompile() has already turned into data-addrs). Persisted, because a
       reading preference that resets every launch is an annoyance, not a feature. */
    var bsy = U.$("#tb-sync");
    if (bsy) {
      S.syncViews = localStorage.getItem("ds.syncViews") !== "0";
      var paint = function () {
        bsy.classList.toggle("on", !!S.syncViews);
        bsy.title = S.syncViews
          ? "Listing and pseudocode follow each other — click to unlink"
          : "Listing and pseudocode move independently — click to link";
      };
      paint();
      bsy.addEventListener("click", function () {
        S.syncViews = !S.syncViews;
        localStorage.setItem("ds.syncViews", S.syncViews ? "1" : "0");
        paint();
        if (S.syncViews) syncPseudoToRva(S.activeRva);
      });
    }

    wireResizers();
    restoreLayout();

    // global search
    U.$("#search-input").addEventListener("input", U.debounce(function () { renderSearch(U.$("#search-input").value); }, 80));
    U.$("#search-input").addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); searchMove(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); searchMove(-1); }
      else if (e.key === "Enter") { e.preventDefault(); pickSearch(searchSel); }
      else if (e.key === "Escape") { e.preventDefault(); closeSearch(); }
    });
    U.$("#search").addEventListener("mousedown", function (e) { if (e.target.id === "search") closeSearch(); });

    document.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === "s" || e.key === "S")) { e.preventDefault(); saveAnalysis(); return; }
      if ((e.ctrlKey || e.metaKey) && (e.key === "f" || e.key === "F")) { e.preventDefault(); openSearch(); return; }
      if (e.key === "Escape") { closeGoto(); closeSearch(); return; }
      if (e.target && e.target.tagName === "INPUT") return;
      if (e.key === "g" || e.key === "G") { e.preventDefault(); openGoto(); }
      else if (e.key === "F5") { e.preventDefault(); setInspView("decompile"); if (S.curFn) decompile(S.curFn); }
      else if (e.key === "/") { e.preventDefault(); U.$("#panel-filter").focus(); }
    });
    window.addEventListener("resize", U.debounce(drawJumpmap, 120));
  }

  /* ---- global search (functions / strings / imports / exports / segments) - */
  var searchSel = 0, searchItems = [];
  function openSearch() {
    var g = U.$("#search"); g.hidden = false;
    requestAnimationFrame(function () { g.classList.add("show"); var i = U.$("#search-input"); i.value = ""; renderSearch(""); i.focus(); });
  }
  function closeSearch() { var g = U.$("#search"); if (g) g.classList.remove("show"); }
  function byQ(q, field) { return function (x) { return (("" + (x[field] || "")).toLowerCase()).indexOf(q) >= 0; }; }
  function renderSearch(q) {
    q = (q || "").toLowerCase().trim();
    var host = U.clear(U.$("#search-results")); searchItems = []; searchSel = 0;
    if (!q) { host.appendChild(U.el("div.sr-empty", { text: "Search functions, strings, imports, exports and segments." })); return; }
    var groups = [
      { key: "FUNCTION", items: S.funcs.filter(byQ(q, "name")).slice(0, 50).map(function (f) { return { kind: "func", label: f.name || ("sub_" + U.hex(f.rva).slice(2)), rva: f.rva }; }) },
      { key: "STRING", items: S.strings.filter(function (s) { return ("" + (s.value || "")).toLowerCase().indexOf(q) >= 0; }).slice(0, 50).map(function (s) { return { kind: "str", label: s.value, rva: s.rva, str: true }; }) },
      { key: "IMPORT", items: S.imports.filter(byQ(q, "name")).slice(0, 40).map(function (i) { return { kind: "imp", label: i.name, rva: i.rva }; }) },
      { key: "EXPORT", items: S.exports.filter(byQ(q, "name")).slice(0, 40).map(function (e) { return { kind: "exp", label: e.name, rva: e.rva }; }) },
      { key: "SEGMENT", items: S.segs.filter(byQ(q, "name")).map(function (g) { return { kind: "seg", label: g.name, rva: g.rva }; }) }
    ];
    var any = false;
    groups.forEach(function (grp) {
      if (!grp.items.length) return; any = true;
      host.appendChild(U.el("div.sr-group", { text: grp.key + "  (" + grp.items.length + ")" }));
      grp.items.forEach(function (it) {
        var idx = searchItems.length; searchItems.push(it);
        host.appendChild(U.el("button.sr-item" + (idx === 0 ? ".on" : ""), { dataset: { i: idx }, onclick: function () { pickSearch(idx); } }, [
          U.el("span.sr-kind", { text: grp.key.slice(0, 3) }),
          U.el("span.sr-label" + (it.str ? ".str" : ""), { text: clip(it.label, 84), title: it.label }),
          U.el("span.sr-addr", { text: U.hex(it.rva) })
        ]));
      });
    });
    if (!any) host.appendChild(U.el("div.sr-empty", { text: "No matches for “" + q + "”." }));
  }
  function pickSearch(i) { var it = searchItems[i]; closeSearch(); if (it) navigate(Number(it.rva)); }
  function searchMove(d) {
    if (!searchItems.length) return;
    searchSel = (searchSel + d + searchItems.length) % searchItems.length;
    U.$all("#search-results .sr-item").forEach(function (n, i) { n.classList.toggle("on", i === searchSel); });
    var cur = U.$('#search-results .sr-item[data-i="' + searchSel + '"]'); if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: "nearest" });
  }
  function openGoto() {
    var g = U.$("#goto"); g.hidden = false; // clears [hidden] so the fade can run
    requestAnimationFrame(function () { g.classList.add("show"); var i = U.$("#goto-input"); i.value = ""; i.focus(); });
  }
  function closeGoto() { var g = U.$("#goto"); if (g) g.classList.remove("show"); }
  function commitGoto() {
    var v = (U.$("#goto-input").value || "").trim(); closeGoto(); if (!v) return;
    if (/^(0x)?[0-9a-f]+$/i.test(v)) { navigate(parseInt(v.replace(/^0x/i, ""), 16)); return; }
    var q = v.toLowerCase();
    var hit = S.funcs.find(byName(q)) || S.exports.find(byName(q)) || S.imports.find(byName(q)) ||
      S.funcs.find(byIncl(q)) || S.strings.find(function (s) { return (s.value || "").toLowerCase().indexOf(q) >= 0; });
    if (hit) navigate(Number(hit.rva)); else U.toast("no match for '" + v + "'", "warn");
  }
  function byName(q) { return function (x) { return (x.name || "").toLowerCase() === q; }; }
  function byIncl(q) { return function (x) { return (x.name || "").toLowerCase().indexOf(q) >= 0; }; }

  function registerCommands() {
    APP.command({ id: "d.search", title: "Search Everything  (Ctrl+F)", group: "Nav", run: openSearch });
    APP.command({ id: "d.goto", title: "Go to Address / Symbol", group: "Nav", keys: ["g"], run: openGoto });
    APP.command({ id: "d.decompile", title: "Decompile Function", group: "View", keys: ["f5"], run: function () { setInspView("decompile"); if (S.curFn) decompile(S.curFn); } });
    APP.command({ id: "d.graph", title: "Show Call Graph", group: "View", run: function () { setInspView("graph"); } });
    APP.command({ id: "d.offsets", title: "Show [reg+disp] Offsets", group: "View", run: function () { setInspView("offsets"); } });
    APP.command({ id: "d.hex", title: "Show Hex Dump", group: "View", run: function () { setInspView("hex"); } });
    APP.command({ id: "d.xrefs", title: "Show Xrefs to Selection", group: "View", run: function () { if (S.activeRva != null) openXrefs(S.activeRva); } });
    APP.command({ id: "d.sm", title: "Toggle 0-goto State Machine", group: "Decompile", run: function () {
      S.smOn = !S.smOn;
      U.$all("#sm-seg .seg-btn").forEach(function (x) { x.classList.toggle("on", x.dataset.sm === (S.smOn ? "1" : "0")); });
      setInspView("decompile"); if (S.curFn) decompile(S.curFn);
    } });
    APP.command({ id: "d.nav.fn", title: "Navigator: Functions", group: "Nav", run: function () { pickPanel("functions"); } });
    APP.command({ id: "d.nav.str", title: "Navigator: Strings", group: "Nav", run: function () { pickPanel("strings"); } });
    APP.command({ id: "d.nav.imp", title: "Navigator: Imports", group: "Nav", run: function () { pickPanel("imports"); } });
    APP.command({ id: "d.panel", title: "Toggle Navigator Panel", group: "View", run: function () { U.$("#ide").classList.toggle("panel-collapsed"); } });
    APP.command({ id: "d.insp", title: "Toggle Inspector Panel", group: "View", run: function () { U.$("#ide").classList.toggle("insp-collapsed"); } });
  }
  function pickPanel(name) { var b = U.$('#activity [data-panel="' + name + '"]'); if (b) b.click(); }
})();
