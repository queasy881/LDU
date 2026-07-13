/* ============================================================================
   disasm.js — the disassembly workspace controller.

   Drives: analysis progress overlay -> functions/segments sidebar -> virtualized
   listing with aligned columns + monochrome highlighting, row selection, copy,
   inline comments, marks, goto, jump history, xrefs, and a shortcuts overlay.
   Talks only to window.DS (invoke/on/off) + window.VList + util globals.
   ========================================================================== */
(function () {
  "use strict";

  var ROW_H = 19;   // listing row height (must match disasm.css slot)
  var FN_H = 22;    // function-list row height
  var CHUNK = 220;  // listing fetch window

  // ---- state ------------------------------------------------------------
  var session = { name: "", path: "", project: "" };
  var funcs = [];           // {rva,name,size,block_count,call_count}
  var imports = [];         // {rva (IAT slot), name}
  var exports = [];         // {rva, name}
  var strings = [];         // {rva, value, kind}  kind 0=ascii 1=utf16
  var segs = [];            // {name,rva,size,flags,r,w,x}
  var activeTab = "functions";
  var sideVList = null, sideQuery = "";
  var listingLen = 0;
  var rowCache = new Map(); // listing index -> row object from backend
  var inflight = new Set(); // chunk-start indices being fetched
  var comments = new Map(); // rva -> text
  var marks = new Set();    // rva (number)
  var selected = new Set(); // selected listing indices
  var cursor = -1, anchor = -1;
  var selectedFnRva = null;
  var history = [];         // jump-back stack of listing indices
  var fwd = [];             // forward stack (after going back)
  var disVList = null;
  var finished = false, pollTimer = 0;

  var renameMap = new Map();  // rva(number) -> custom display name (persisted)
  var symByName = new Map();  // lowercased original symbol name -> rva
  var symRvas = new Set();    // set of all function rvas (fast "is a symbol")
  var hlToken = "";           // currently highlighted operand token (occurrences)

  function $(id) { return document.getElementById(id); }
  function isTyping() { var a = document.activeElement; return a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.isContentEditable); }
  function hasTextSelection() { var s = window.getSelection(); return s && s.type === "Range" && String(s).trim().length > 0; }

  // ---- persisted rename map (per binary) --------------------------------
  function renameKey() { return "rename:" + (session.path || session.name || "bin"); }
  function loadRenames() {
    renameMap = new Map();
    try {
      var raw = localStorage.getItem(renameKey());
      if (raw) { var o = JSON.parse(raw); Object.keys(o).forEach(function (k) { renameMap.set(Number(k), o[k]); }); }
    } catch (e) {}
  }
  function saveRenames() {
    try {
      var o = {}; renameMap.forEach(function (v, k) { o[k] = v; });
      localStorage.setItem(renameKey(), JSON.stringify(o));
    } catch (e) {}
  }
  // The display name for an rva: a user rename wins, else the original symbol.
  function displayName(rva, fallback) {
    if (rva != null && renameMap.has(Number(rva))) return renameMap.get(Number(rva));
    return fallback;
  }

  // ====================================================================== boot
  (function waitReady() {
    if (!window.DS || !window.VList || !window.DSUtil) { return void setTimeout(waitReady, 20); }
    init();
  })();

  function init() {
    buildHelp();
    wireToolbar();
    wireKeyboard();

    DS.invoke("get_session_info").then(function (s) {
      session = s || session;
      $("an-target").textContent = session.name ? (session.name + (session.project ? "   ·   " + session.project : "")) : (session.path || "");
      $("ws-loc").textContent = session.name || "";
      document.title = "DisasmStudio — " + (session.name || "");
    }).catch(function () {});

    var onProg = function (m) { if (!finished) updateProgress(m); };
    var onDone = function () { finish(); };
    var onErr = function (m) { showError(m && m.message ? m.message : "analysis error"); };
    DS.on("analysis_progress", onProg);
    DS.on("analysis_done", onDone);
    DS.on("analysis_error", onErr);

    // Fallback for a missed analysis_done (event raced our subscription):
    // poll get_binary_meta; it errors until analysis commits, then succeeds.
    pollTimer = setInterval(function () {
      DS.invoke("get_binary_meta").then(function () { finish(); }).catch(function () {});
    }, 500);
  }

  // =============================================================== analysis UI
  function updateProgress(m) {
    if (m.stage) $("analysis-stage").textContent = m.stage;
    var pct = Math.max(0, Math.min(100, +m.pct || 0));
    $("analysis-bar").style.width = pct + "%";
    $("analysis-pct").textContent = Math.round(pct) + "%";
  }

  function showError(msg) {
    $("an-running").hidden = true;
    $("analysis-error").hidden = false;
    $("analysis-error-msg").textContent = msg;
  }

  function finish() {
    if (finished) return;
    finished = true;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = 0; }
    $("analysis-overlay").classList.add("done");
    loadWorkspace();
  }

  function wireToolbar() {
    $("ws-back").addEventListener("click", goBack);
    $("ws-goto").addEventListener("click", openGoto);
    $("ws-decompile").addEventListener("click", toggleDecompile);
    $("decomp-close").addEventListener("click", function () { setDecompOpen(false); });
    wireDecompResizer();
    $("decomp-copy").addEventListener("click", function () { copyText($("decomp-code").textContent || ""); flashLoc("copied"); });
    $("ws-help").addEventListener("click", toggleHelp);
    $("analysis-cancel").addEventListener("click", function () {
      DS.invoke("cancel_analysis").catch(function () {});
      $("analysis-stage").textContent = "Cancelled";
    });
    $("analysis-retry").addEventListener("click", function () {
      $("analysis-error").hidden = true; $("an-running").hidden = false;
      // analysis is backend-driven; resume polling for completion.
      finished = false;
      if (!pollTimer) pollTimer = setInterval(function () {
        DS.invoke("get_binary_meta").then(function () { finish(); }).catch(function () {});
      }, 500);
    });
    $("xref-head").addEventListener("click", function () { $("xref-bar").classList.toggle("collapsed"); });

    // click a call target inside the pseudocode -> jump to that function's disasm
    $("decomp-code").addEventListener("click", function (e) {
      if (hasTextSelection()) return;
      var c = e.target.closest(".pc-call"); if (!c) return;
      var sym = c.dataset.sym || ""; var rva = null;
      var mm = sym.match(/^(?:fun|sub|j)_0*([0-9a-fA-F]+)$/);
      if (mm) rva = parseInt(mm[1], 16);
      else if (symByName.has(sym.toLowerCase())) rva = symByName.get(sym.toLowerCase());
      if (rva != null) { pushHistory(); jumpToRva(rva); var f = funcAt(rva); if (f) decompileRva(f); }
    });
  }

  // ================================================================ workspace
  function loadWorkspace() {
    Promise.all([
      DS.invoke("get_functions").catch(function () { return []; }),
      DS.invoke("get_segments").catch(function () { return []; }),
      DS.invoke("get_imports").catch(function () { return []; }),
      DS.invoke("get_exports").catch(function () { return []; }),
      DS.invoke("get_strings").catch(function () { return []; }),
      DS.invoke("get_listing_len").catch(function () { return { len: 0 }; }),
      DS.invoke("get_comments").catch(function () { return {}; }),
      DS.invoke("get_marks").catch(function () { return []; })
    ]).then(function (r) {
      funcs = r[0] || [];
      segs = r[1] || [];
      imports = r[2] || [];
      exports = r[3] || [];
      strings = r[4] || [];
      listingLen = (r[5] && r[5].len) | 0;
      comments = new Map();
      var cm = r[6] || {};
      Object.keys(cm).forEach(function (k) { comments.set(Number(k), cm[k]); });
      marks = new Set((r[7] || []).map(Number));

      // symbol index: original name -> rva, for clickable named operands + rename
      symByName = new Map(); symRvas = new Set();
      funcs.forEach(function (f) { if (f.name) symByName.set(f.name.toLowerCase(), f.rva); symRvas.add(f.rva); });
      imports.forEach(function (im) { if (im.name) symByName.set(im.name.toLowerCase(), im.rva); });
      loadRenames();

      buildSidebar();
      buildListing();
      buildToolbarExtras();
      $("ws-meta").textContent =
        funcs.length + " fns · " + imports.length + " imp · " + exports.length +
        " exp · " + listingLen.toLocaleString() + " lines";
    });
  }

  // ---- tabbed sidebar: functions / imports / exports / segments ---------
  function tabList(tab) {
    return tab === "functions" ? funcs : tab === "imports" ? imports
         : tab === "exports" ? exports : tab === "strings" ? strings : segs;
  }

  function buildSidebar() {
    var tabs = document.querySelectorAll(".side-tab");
    Array.prototype.forEach.call(tabs, function (t) {
      t.addEventListener("click", function () { setTab(t.dataset.tab); });
    });
    var doFilter = debounce(function (q) { sideQuery = q.trim().toLowerCase(); renderSide(); }, 80);
    $("fn-filter").addEventListener("input", function (e) { doFilter(e.target.value); });

    setTab("functions");
  }

  function setTab(tab) {
    activeTab = tab;
    Array.prototype.forEach.call(document.querySelectorAll(".side-tab"), function (t) {
      classToggle(t, "active", t.dataset.tab === tab);
    });
    var f = $("fn-filter");
    f.value = ""; sideQuery = "";
    f.placeholder = "filter " + tab + "   /";
    renderSide();
  }

  function filteredList() {
    var list = tabList(activeTab);
    if (!sideQuery) return list;
    var q = sideQuery;
    if (activeTab === "segments") {
      return list.filter(function (s) { return s.name.toLowerCase().indexOf(q) >= 0; });
    }
    return list.filter(function (it) {
      var t = (it.name || it.value || "").toLowerCase();
      return t.indexOf(q) >= 0 || fmtAddr(it.rva).indexOf(q) >= 0;
    });
  }

  function emptyMsg(tab) {
    switch (tab) {
      case "exports": return "No exports.\nThis binary has no export table (e.g. an injected / manually-mapped DLL).";
      case "imports": return "No imports.";
      case "functions": return "No functions recovered.";
      case "segments": return "No segments.";
      default: return "Nothing here.";
    }
  }

  function renderSide() {
    var list = filteredList();
    var host = $("side-list");
    var cnt = $("side-count");
    if (cnt) cnt.textContent = list.length.toLocaleString();
    if (sideVList) { sideVList.destroy(); sideVList = null; }
    clear(host);
    if (!list.length) {
      host.appendChild(el("div", { class: "side-empty", text: sideQuery ? "No matches for “" + sideQuery + "”" : emptyMsg(activeTab) }));
      return;
    }
    var tab = activeTab;
    sideVList = new VList(host, {
      rowHeight: FN_H, total: list.length,
      render: function (i) { return sideRow(tab, list[i]); }
    });
  }

  function sideRow(tab, item) {
    if (!item) return el("div", { class: "fn-row" });
    if (tab === "strings") {
      return el("div", {
        class: "fn-row str-row", title: item.value,
        onclick: function () { loadXrefs(item.rva, '"' + item.value + '"', true); }
      }, [
        el("span", { class: "a", text: fmtAddr(item.rva) }),
        el("span", { class: "n", text: (item.kind === 1 ? 'L"' : '"') + item.value + '"' })
      ]);
    }
    if (tab === "segments") {
      var perm = (item.r ? "R" : "-") + (item.w ? "W" : "-") + (item.x ? "X" : "-");
      return el("div", { class: "seg-row", onclick: function () { jumpToRva(item.rva); } }, [
        el("span", { class: "sn", text: item.name }),
        el("span", { class: "sa", text: fmtAddr(item.rva) }),
        el("span", { class: "ss", text: hex(item.size) }),
        el("span", { class: "perm", text: perm })
      ]);
    }
    var thunk = tab === "functions" && /^j_/.test(item.name || "");
    var isSel = tab === "functions" && item.rva === selectedFnRva;
    var nm = (tab === "functions" || tab === "imports" || tab === "exports") ? displayName(item.rva, item.name) : item.name;
    var renamed = (tab === "functions") && renameMap.has(Number(item.rva));
    return el("div", {
      class: "fn-row" + (thunk ? " thunk" : "") + (isSel ? " sel" : ""),
      title: nm + (renamed ? "  (was " + item.name + ")" : ""),
      oncontextmenu: function (e) {
        if (tab === "functions") { e.preventDefault(); openRename(item.rva, item.name, e.clientX, e.clientY); }
      },
      onclick: function () {
        if (tab === "functions") {
          selectedFnRva = item.rva; if (sideVList) sideVList.refresh();
          decompFollow(item.rva);   // live-update the pseudocode panel if open
        }
        jumpToRva(item.rva);
        loadXrefs(item.rva, nm);
      }
    }, [
      el("span", { class: "a", text: fmtAddr(item.rva) }),
      el("span", { class: "n" + (renamed ? " renamed" : ""), text: nm })
    ]);
  }

  // ---- the listing ------------------------------------------------------
  function buildListing() {
    var host = $("disasm-view");
    clear(host); rowCache = new Map(); inflight = new Set();
    disVList = new VList(host, {
      rowHeight: ROW_H, total: listingLen, overscan: 10,
      render: function (i) {
        var r = rowCache.get(i);
        if (!r) { fetchChunk(Math.floor(i / CHUNK) * CHUNK); return placeholder(); }
        return buildRow(i, r);
      }
    });
    host.addEventListener("click", onListingClick);
    host.addEventListener("dblclick", onListingDblClick);
    host.addEventListener("contextmenu", onListingCtx);
  }

  function placeholder() { return el("div", { class: "ds-row" }, el("span", { class: "ds-addr" })); }

  function fetchChunk(start) {
    if (inflight.has(start) || rowCache.has(start)) return;
    inflight.add(start);
    DS.invoke("get_disassembly", { start: start, count: CHUNK }).then(function (rows) {
      (rows || []).forEach(function (row, k) { rowCache.set(start + k, row); });
      inflight.delete(start);
      if (disVList) disVList.refresh();
    }).catch(function () { inflight.delete(start); });
  }

  // whole-token x86-64 register matcher
  var REG_RE = /^(?:[re]?[abcd]x|[re]?[sb]p|[re]?[sd]i|r(?:8|9|1[0-5])[dwb]?|[abcd][lh]|[sb]pl|[sd]il|[xyz]mm\d{1,2}|[re]ip|[cdefgs]s|cr\d|dr\d|st\d?)$/i;
  var TOKEN_RE = /(0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_.]*|\d+)/g;

  function hlAttr(tok) { return ' data-tok="' + DSUtil.escapeHtml(tok) + '"'; }
  function hlCls(tok) { return (hlToken && tok.toLowerCase() === hlToken) ? " tok-hl" : ""; }

  // Tokenize an operand string: colour registers / immediates, make the jump/
  // call/data target AND any named symbol clickable (with the renamed label),
  // and tag every token for the click-to-highlight-all-occurrences feature.
  function escapeOps(text, refTarget) {
    if (!text) return "";
    var tgt = (refTarget != null) ? Number(refTarget) : null;
    return text.replace(TOKEN_RE, function (m) {
      var esc = DSUtil.escapeHtml(m);
      if (/^0x/i.test(m) || /^\d+$/.test(m)) {
        var val = /^0x/i.test(m) ? parseInt(m, 16) : parseInt(m, 10);
        if (tgt != null && val === tgt) {
          var nm = displayName(tgt, null) || m;
          return '<span class="ds-ref' + hlCls(nm) + '" data-rva="' + tgt + '"' + hlAttr(nm.toLowerCase()) + '>' + DSUtil.escapeHtml(nm) + '</span>';
        }
        return '<span class="ds-imm' + hlCls(m) + '"' + hlAttr(m.toLowerCase()) + '>' + esc + '</span>';
      }
      if (REG_RE.test(m)) return '<span class="ds-reg' + hlCls(m) + '"' + hlAttr(m.toLowerCase()) + '>' + esc + '</span>';
      var lc = m.toLowerCase();
      if (symByName.has(lc)) {
        var rva = symByName.get(lc), dn = displayName(rva, m);
        return '<span class="ds-ref' + hlCls(dn) + '" data-rva="' + rva + '"' + hlAttr(dn.toLowerCase()) + '>' + DSUtil.escapeHtml(dn) + '</span>';
      }
      return '<span' + hlAttr(lc) + (hlCls(m) ? ' class="tok-hl"' : '') + '>' + esc + '</span>';
    });
  }

  function buildRow(i, r) {
    if (r.kind === "segment") {
      var perm = (r.r ? "R" : "-") + (r.w ? "W" : "-") + (r.x ? "X" : "-");
      return el("div", { class: "ds-seg", dataset: { index: i } }, [
        el("span", { class: "lbl", text: "Segment" }),
        el("span", { class: "nm", text: r.name }),
        el("span", { class: "mt", text: fmtAddr(r.rva) + "  ·  " + hex(r.size) }),
        el("span", { class: "pm", text: perm })
      ]);
    }
    if (r.kind === "func") {
      var rn = renameMap.has(Number(r.rva));
      return el("div", { class: "ds-fn", dataset: { index: i, rva: r.rva } }, [
        el("span", { class: "fnm" + (rn ? " renamed" : ""), text: displayName(r.rva, r.name) }),
        el("span", { class: "fmt", text: r.size + " bytes  ·  " + r.block_count + " block" + (r.block_count === 1 ? "" : "s") })
      ]);
    }
    if (r.kind === "data") {
      var cls = "ds-data" + (selected.has(i) ? " sel" : "") + (i === cursor ? " cursor" : "");
      return el("div", { class: cls, dataset: { index: i, rva: r.rva } }, [
        el("span", { class: "ds-gut" }),
        el("span", { class: "ds-addr", text: fmtAddr(r.rva) }),
        el("span", { class: "ds-bytes", text: r.bytes }),
        el("span", { class: "ds-ascii", text: r.ascii })
      ]);
    }
    // insn
    var marked = marks.has(r.rva);
    var cl = "ds-row" + (selected.has(i) ? " sel" : "") + (i === cursor ? " cursor" : "") + (marked ? " marked" : "");
    var opsHtml = escapeOps(r.operands, r.ref_target);
    var cmt = comments.get(r.rva);
    if (cmt) opsHtml += '<span class="ds-cmt">; ' + DSUtil.escapeHtml(cmt) + "</span>";
    return el("div", { class: cl, dataset: { index: i, rva: r.rva } }, [
      el("span", { class: "ds-gut" }),
      el("span", { class: "ds-addr", text: fmtAddr(r.rva) }),
      el("span", { class: "ds-bytes", text: r.bytes }),
      el("span", { class: "ds-mn", text: r.mnemonic }),
      el("span", { class: "ds-ops", html: opsHtml })
    ]);
  }

  // ---- listing interaction ---------------------------------------------
  function onListingClick(e) {
    // a real text drag-select must NOT be hijacked into a row-select
    if (hasTextSelection()) return;
    var ref = e.target.closest(".ds-ref");
    if (ref && !e.altKey) { e.stopPropagation(); pushHistory(); jumpToRva(Number(ref.dataset.rva)); return; }
    var row = e.target.closest(".ds-row, .ds-data");
    if (!row || row.dataset.index == null) return;
    var i = +row.dataset.index;
    // click a token (register / immediate / symbol) -> highlight all occurrences
    var tokEl = e.target.closest("[data-tok]");
    if (tokEl && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      var tok = tokEl.dataset.tok;
      hlToken = (hlToken === tok) ? "" : tok;     // toggle
      selectOne(i); return;
    }
    if (e.shiftKey) selectRange(anchor < 0 ? i : anchor, i);
    else if (e.ctrlKey || e.metaKey) toggleSel(i);
    else selectOne(i);
  }

  function onListingDblClick(e) {
    var ref = e.target.closest(".ds-ref");
    if (ref) { e.preventDefault(); pushHistory(); jumpToRva(Number(ref.dataset.rva)); return; }
    // double-click on a function banner / body -> decompile it
    decompileCurrent();
  }

  function onListingCtx(e) {
    var row = e.target.closest(".ds-row, .ds-data, .ds-fn");
    if (!row) return;
    e.preventDefault();
    if (row.dataset.index != null && !hasTextSelection()) {
      var i = +row.dataset.index; if (!selected.has(i)) selectOne(i);
    }
    showContextMenu(e.clientX, e.clientY, e.target.closest(".ds-ref"), e.target.closest("[data-tok]"));
  }

  function selectOne(i) { selected = new Set([i]); cursor = i; anchor = i; repaintListing(); }
  function toggleSel(i) { if (selected.has(i)) selected.delete(i); else selected.add(i); cursor = i; anchor = i; repaintListing(); }
  function selectRange(a, b) {
    selected = new Set(); var lo = Math.min(a, b), hi = Math.max(a, b);
    for (var k = lo; k <= hi; k++) selected.add(k);
    cursor = b; repaintListing();
  }
  function repaintListing() { if (disVList) disVList.refresh(); updateSelChip(); }

  function moveCursor(delta, extend) {
    if (listingLen === 0) return;
    var n = cursor < 0 ? 0 : cursor + delta;
    n = Math.max(0, Math.min(listingLen - 1, n));
    if (extend) { if (anchor < 0) anchor = cursor < 0 ? n : cursor; selectRange(anchor, n); }
    else selectOne(n);
    cursor = n;
    if (disVList) disVList.scrollToIndex(n, "center");
    repaintListing();
  }

  // ---- navigation -------------------------------------------------------
  function pushHistory() { if (cursor >= 0) { history.push(cursor); fwd = []; } }
  function jumpToRva(rva, noHistory) {
    DS.invoke("get_row_for_rva", { rva: rva }).then(function (d) {
      var idx = d && d.index;
      if (idx == null || idx < 0) { flashLoc("no address " + fmtAddr(rva)); return; }
      if (!noHistory && cursor >= 0 && cursor !== idx) { history.push(cursor); fwd = []; }
      selectOne(idx); cursor = idx;
      if (disVList) disVList.scrollToIndex(idx, "center");
      $("ws-loc").textContent = fmtAddr(rva);
    }).catch(function () {});
  }
  function goBack() { if (!history.length) return; if (cursor >= 0) fwd.push(cursor); var i = history.pop(); selectOne(i); cursor = i; if (disVList) disVList.scrollToIndex(i, "center"); }
  function goFwd() { if (!fwd.length) return; if (cursor >= 0) history.push(cursor); var i = fwd.pop(); selectOne(i); cursor = i; if (disVList) disVList.scrollToIndex(i, "center"); }

  // ---- decompiler -------------------------------------------------------
  function funcAt(rva) {
    for (var i = 0; i < funcs.length; i++) {
      var f = funcs[i];
      if (rva >= f.rva && rva < f.rva + f.size) return f;
    }
    for (var k = 0; k < funcs.length; k++) if (funcs[k].rva === rva) return funcs[k];
    return null;
  }

  var decompSeq = 0;   // guards against out-of-order async results while live-following

  function decompIsOpen() { return !$("decomp-overlay").hidden; }

  // Show/hide the side panel AND its drag handle together.
  function setDecompOpen(open) {
    $("decomp-overlay").hidden = !open;
    $("decomp-resizer").hidden = !open;
  }

  var decompRawText = "";   // last pseudocode (raw, for find + copy)

  // Decompile a specific function into the panel (opening it if needed).
  function decompileRva(f) {
    if (!f) return;
    setDecompOpen(true);
    $("decomp-title").textContent = displayName(f.rva, f.name) + "   " + fmtAddr(f.rva);
    $("decomp-code").textContent = "decompiling…";
    var seq = ++decompSeq;
    DS.invoke("get_pseudocode", { rva: f.rva }).then(function (d) {
      if (seq !== decompSeq) return;   // a newer selection superseded this one
      var code = (d && d.code) ? d.code : "/* (empty) */";
      code = applyRenamesToText(code);
      decompRawText = code;
      $("decomp-code").innerHTML = highlightPseudocode(code);
    }).catch(function (e) {
      if (seq !== decompSeq) return;
      decompRawText = "";
      $("decomp-code").textContent = "/* error: " + (e && e.message ? e.message : e) + " */";
    });
  }

  // Rewrite fun_<rva> / sub_<rva> tokens in pseudocode with their renamed names.
  function applyRenamesToText(code) {
    if (!renameMap.size) return code;
    return code.replace(/\b(?:fun|sub|j)_0*([0-9a-fA-F]+)\b/g, function (m, hx) {
      var rva = parseInt(hx, 16);
      return renameMap.has(rva) ? renameMap.get(rva) : m;
    });
  }

  // Lightweight C tokenizer -> Platinum syntax spans. Call targets (fun_/sub_/
  // identifiers immediately before "(") get the clickable .pc-call class.
  var PC_KW = /\b(if|else|while|for|do|switch|case|default|break|continue|return|goto|sizeof)\b/;
  var PC_TYPE = /\b(void|char|short|int|long|unsigned|signed|float|double|bool|struct|union|enum|const|static|volatile|__int64|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|size_t)\b/;
  function highlightPseudocode(code) {
    var out = "";
    var re = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|("(?:\\.|[^"\\])*")|(\b0x[0-9a-fA-F]+\b|\b\d+\.?\d*[fFuUlL]*\b)|([A-Za-z_][A-Za-z0-9_]*)|([{}()\[\];,]|->|[+\-*/%&|^!<>=~?:.])/g;
    var last = 0, m;
    while ((m = re.exec(code)) !== null) {
      if (m.index > last) out += DSUtil.escapeHtml(code.slice(last, m.index));
      last = re.lastIndex;
      if (m[1]) out += '<span class="pc-cmt">' + DSUtil.escapeHtml(m[1]) + '</span>';
      else if (m[2]) out += '<span class="pc-str">' + DSUtil.escapeHtml(m[2]) + '</span>';
      else if (m[3]) out += '<span class="pc-num">' + DSUtil.escapeHtml(m[3]) + '</span>';
      else if (m[4]) {
        var w = m[4], esc = DSUtil.escapeHtml(w);
        var after = code.slice(re.lastIndex).match(/^\s*\(/);
        if (PC_KW.test(w)) out += '<span class="pc-kw">' + esc + '</span>';
        else if (PC_TYPE.test(w)) out += '<span class="pc-type">' + esc + '</span>';
        else if (after && /^(fun|sub|j)_|^[a-z]/i.test(w)) out += '<span class="pc-call" data-sym="' + esc + '">' + esc + '</span>';
        else if (/^(fun|sub|j)_[0-9a-f]+$/i.test(w)) out += '<span class="pc-fn">' + esc + '</span>';
        else out += '<span class="pc-id" data-tok="' + esc.toLowerCase() + '">' + esc + '</span>';
      } else if (m[5]) out += '<span class="pc-punc">' + DSUtil.escapeHtml(m[5]) + '</span>';
    }
    if (last < code.length) out += DSUtil.escapeHtml(code.slice(last));
    return out;
  }

  function decompileCurrent() {
    var r = cursorRow();
    var rva = (r && r.rva != null) ? r.rva : (selectedFnRva != null ? selectedFnRva : null);
    var f = (rva != null) ? funcAt(rva) : null;
    if (!f && selectedFnRva != null) f = funcAt(selectedFnRva);
    if (!f) { flashLoc("no function here"); return; }
    decompileRva(f);
  }

  // Called when the function selection changes on the left: if the panel is
  // open, retarget it live to the newly-selected function.
  function decompFollow(rva) {
    if (!decompIsOpen()) return;
    var f = (rva != null) ? funcAt(rva) : null;
    if (f) decompileRva(f);
  }

  function toggleDecompile() {
    if (decompIsOpen()) { setDecompOpen(false); return; }
    decompileCurrent();
  }

  // ---- pseudocode panel resizer ----------------------------------------
  function wireDecompResizer() {
    var rez = $("decomp-resizer"), main = $("ws-main");
    if (!rez || !main) return;
    var saved = parseInt(localStorage.getItem("decompW") || "", 10);
    if (saved >= 320) main.style.setProperty("--decomp-w", saved + "px");
    var dragging = false;
    rez.addEventListener("mousedown", function (e) {
      dragging = true; rez.classList.add("drag");
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
      e.preventDefault();
    });
    window.addEventListener("mousemove", function (e) {
      if (!dragging) return;
      var rect = main.getBoundingClientRect();
      var w = rect.right - e.clientX;                 // panel hugs the right edge
      w = Math.max(320, Math.min(w, rect.width * 0.72));
      main.style.setProperty("--decomp-w", Math.round(w) + "px");
    });
    window.addEventListener("mouseup", function () {
      if (!dragging) return;
      dragging = false; rez.classList.remove("drag");
      document.body.style.cursor = ""; document.body.style.userSelect = "";
      var cur = getComputedStyle(main).getPropertyValue("--decomp-w").trim();
      var px = parseInt(cur, 10);
      if (px >= 320) localStorage.setItem("decompW", String(px));
    });
  }

  // ---- xrefs ------------------------------------------------------------
  function isExecRva(rva) {
    for (var i = 0; i < segs.length; i++) {
      var s = segs[i];
      if (s.x && rva >= s.rva && rva < s.rva + s.size) return true;
    }
    return false;
  }

  function loadXrefs(rva, name, jumpFirst) {
    DS.invoke("get_xrefs_to", { rva: rva }).then(function (xs) {
      xs = xs || [];
      $("xref-to").textContent = (name || fmtAddr(rva));
      $("xref-count").textContent = xs.length + " ref" + (xs.length === 1 ? "" : "s");
      var host = clear($("xref-chips"));
      if (!xs.length) { host.appendChild(el("div", { class: "xref-empty", text: "no cross-references" })); }
      xs.forEach(function (x) {
        var kind = x.type === 1 ? "CALL" : x.type === 2 ? "JMP" : x.type === 3 ? "DATA" : "REF";
        host.appendChild(el("div", {
          class: "xchip", onclick: function () { jumpToRva(x.from_rva); }
        }, [el("span", { class: "k", text: kind }), el("span", { text: fmtAddr(x.from_rva) })]));
      });
      $("xref-bar").classList.remove("collapsed");
      // For strings (and any "jump to first use" caller): prefer a CODE
      // reference (an instruction that uses it). If a string is only reached via
      // a data pointer table, fall back to that data ref; if nothing references
      // it at all, fall back to the string's own data location.
      if (jumpFirst) {
        var codeRef = null;
        for (var i = 0; i < xs.length; i++) {
          if (isExecRva(xs[i].from_rva)) { codeRef = xs[i]; break; }
        }
        jumpToRva(codeRef ? codeRef.from_rva : (xs.length ? xs[0].from_rva : rva));
      }
    }).catch(function () { if (jumpFirst) jumpToRva(rva); });
  }

  // ---- comments / marks -------------------------------------------------
  function cursorRow() { return cursor >= 0 ? rowCache.get(cursor) : null; }

  function editComment() {
    var r = cursorRow();
    if (!r || (r.kind !== "insn" && r.kind !== "data")) return;
    var rva = r.rva;
    var host = $("ws-main");
    var prev = host.querySelector(".cmt-edit-wrap"); if (prev) prev.remove();
    var view = $("disasm-view");
    var y = (cursor * ROW_H) - view.scrollTop;
    var wrap = el("div", { class: "cmt-edit-wrap", style: { position: "absolute", left: "0", right: "0", top: y + "px" } });
    var input = el("input", { class: "input cmt-edit", value: comments.get(rva) || "", placeholder: "; comment at " + fmtAddr(rva) });
    wrap.appendChild(input);
    host.appendChild(wrap);
    input.focus(); input.select();
    function done(save) {
      if (save) {
        var t = input.value.trim();
        DS.invoke("set_comment", { rva: rva, text: t }).catch(function () {});
        if (t) comments.set(rva, t); else comments.delete(rva);
      }
      wrap.remove(); repaintListing();
    }
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); done(true); }
      else if (e.key === "Escape") { e.preventDefault(); done(false); }
      e.stopPropagation();
    });
    input.addEventListener("blur", function () { done(false); });
  }

  function toggleMark() {
    var r = cursorRow(); if (!r || r.rva == null) return;
    DS.invoke("toggle_mark", { rva: r.rva }).then(function (d) {
      if (d && d.marked) marks.add(r.rva); else marks.delete(r.rva);
      repaintListing();
    }).catch(function () {});
  }
  function jumpMark(dir) {
    if (!marks.size) return;
    var arr = Array.from(marks).sort(function (a, b) { return a - b; });
    var cur = cursorRow();
    var here = cur ? cur.rva : 0;
    var target = null;
    if (dir > 0) { for (var i = 0; i < arr.length; i++) if (arr[i] > here) { target = arr[i]; break; } if (target == null) target = arr[0]; }
    else { for (var j = arr.length - 1; j >= 0; j--) if (arr[j] < here) { target = arr[j]; break; } if (target == null) target = arr[arr.length - 1]; }
    jumpToRva(target);
  }

  // ---- copy -------------------------------------------------------------
  function copySelection(addrOnly) {
    if (!selected.size) return;
    var idx = Array.from(selected).sort(function (a, b) { return a - b; });
    var lines = [];
    idx.forEach(function (i) {
      var r = rowCache.get(i); if (!r) return;
      if (r.kind === "insn") {
        if (addrOnly) lines.push(fmtAddr(r.rva));
        else {
          var c = comments.get(r.rva);
          lines.push(fmtAddr(r.rva) + "  " + r.mnemonic + " " + r.operands + (c ? "   ; " + c : ""));
        }
      } else if (r.kind === "data") {
        lines.push(addrOnly ? fmtAddr(r.rva) : (fmtAddr(r.rva) + "  " + r.bytes + "  " + r.ascii));
      } else if (r.kind === "func") { if (!addrOnly) lines.push("; " + r.name); }
      else if (r.kind === "segment") { if (!addrOnly) lines.push("; SEGMENT " + r.name); }
    });
    copyText(lines.join("\n"));
    flashLoc("copied " + idx.length + " line" + (idx.length === 1 ? "" : "s"));
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).catch(fb); }
    else fb();
    function fb() {
      var ta = el("textarea", { style: { position: "fixed", opacity: "0", top: "0" } }); ta.value = text;
      document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); } catch (e) {} document.body.removeChild(ta);
    }
  }
  var locTimer = 0;
  function flashLoc(msg) {
    var loc = $("ws-loc"); var old = loc.textContent; loc.textContent = msg;
    if (locTimer) clearTimeout(locTimer);
    locTimer = setTimeout(function () { loc.textContent = old; }, 1400);
  }

  // ---- goto -------------------------------------------------------------
  function openGoto() {
    var existing = document.querySelector(".goto-pop"); if (existing) { existing.remove(); return; }
    var pop = el("div", { class: "goto-pop" });
    var input = el("input", { class: "input", placeholder: "address  e.g. 0x1a7e0", spellcheck: "false" });
    pop.appendChild(input);
    $("ws-bar").appendChild(pop);
    input.focus();
    function close() { pop.remove(); }
    input.addEventListener("keydown", function (e) {
      e.stopPropagation();
      if (e.key === "Enter") {
        var v = input.value.trim().replace(/^0x/i, "");
        var n = /^[0-9a-fA-F]+$/.test(v) ? parseInt(v, 16) : NaN;
        if (!isNaN(n)) jumpToRva(n);
        close();
      } else if (e.key === "Escape") { close(); }
    });
    input.addEventListener("blur", close);
  }

  // ====================================================================== UX+
  // toolbar extras: live selection-count chip; one-time DOM for menus/toast.
  function buildToolbarExtras() {
    if (!$("sel-chip")) {
      var chip = el("span", { id: "sel-chip", hidden: "" });
      var meta = $("ws-meta"); meta.parentNode.insertBefore(chip, meta);
    }
    if (!$("toast")) document.body.appendChild(el("div", { id: "toast" }));
    var dc = $("decomp-code"); if (dc) dc.classList.add("selectable");
    updateSelChip();
  }
  function updateSelChip() {
    var chip = $("sel-chip"); if (!chip) return;
    if (selected.size > 1) { chip.hidden = false; chip.textContent = selected.size + " selected"; }
    else chip.hidden = true;
  }

  var toastTimer = 0;
  function toast(msg, accent) {
    var t = $("toast"); if (!t) return;
    t.innerHTML = accent ? ('<span class="t-accent">' + DSUtil.escapeHtml(accent) + '</span>  ' + DSUtil.escapeHtml(msg)) : DSUtil.escapeHtml(msg);
    t.classList.add("show");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 1800);
  }

  function refreshAll() {
    if (sideVList) sideVList.refresh();
    if (disVList) disVList.refresh();
    if (decompIsOpen()) { var t = $("decomp-title").textContent || ""; var mm = t.match(/0x[0-9a-f]+/i); if (mm) { var f = funcAt(parseInt(mm[0], 16)); if (f) decompileRva(f); } }
  }

  // ---- context menu -----------------------------------------------------
  function closeContextMenu() { var m = $("ctx-menu"); if (m) m.remove(); }
  function showContextMenu(x, y, refEl, tokEl) {
    closeContextMenu();
    var r = cursorRow();
    var rva = r && r.rva != null ? r.rva : null;
    var fn = rva != null ? funcAt(rva) : null;
    var items = [];
    if (refEl) items.push(["Follow reference", "↵ / dblclick", function () { pushHistory(); jumpToRva(Number(refEl.dataset.rva)); }]);
    if (tokEl && tokEl.dataset.tok) items.push(["Highlight all “" + tokEl.dataset.tok + "”", "", function () { hlToken = (hlToken === tokEl.dataset.tok) ? "" : tokEl.dataset.tok; repaintListing(); }]);
    if (refEl || tokEl) items.push(["---"]);
    items.push(["Copy line(s)", "Ctrl+C", function () { copySelection(false); }]);
    items.push(["Copy address(es)", "Ctrl+Shift+C", function () { copySelection(true); }]);
    if (hasTextSelection()) items.push(["Copy selection", "", function () { copyText(String(window.getSelection())); toast("copied selection"); }]);
    items.push(["---"]);
    if (fn) items.push(["Rename " + displayName(fn.rva, fn.name) + "…", "N", function () { openRename(fn.rva, fn.name, x, y); }]);
    items.push(["Edit comment…", ";", function () { editComment(); }]);
    items.push([(rva != null && marks.has(rva)) ? "Remove mark" : "Add mark", "M", function () { toggleMark(); }]);
    items.push(["---"]);
    if (rva != null) items.push(["Cross-references…", "X", function () { loadXrefs(rva, fn ? displayName(fn.rva, fn.name) : fmtAddr(rva)); }]);
    if (fn) items.push(["Decompile function", "F5", function () { decompileRva(fn); }]);

    var menu = el("div", { id: "ctx-menu" });
    items.forEach(function (it) {
      if (it[0] === "---") { menu.appendChild(el("div", { class: "ctx-sep" })); return; }
      menu.appendChild(el("div", { class: "ctx-item", onmousedown: function (e) { e.preventDefault(); closeContextMenu(); it[2](); } },
        [el("span", { text: it[0] }), el("span", { class: "ctx-key", text: it[1] || "" })]));
    });
    document.body.appendChild(menu);
    var mw = menu.offsetWidth, mh = menu.offsetHeight;
    menu.style.left = Math.min(x, window.innerWidth - mw - 8) + "px";
    menu.style.top = Math.min(y, window.innerHeight - mh - 8) + "px";
    setTimeout(function () { document.addEventListener("mousedown", onDocDown, true); }, 0);
    function onDocDown(e) { if (!menu.contains(e.target)) { closeContextMenu(); document.removeEventListener("mousedown", onDocDown, true); } }
  }

  // ---- rename -----------------------------------------------------------
  function openRename(rva, origName, x, y) {
    var prev = document.querySelector(".rename-pop"); if (prev) prev.remove();
    var pop = el("div", { class: "rename-pop" });
    pop.appendChild(el("div", { class: "rn-label", text: "Rename  ·  " + fmtAddr(rva) }));
    var input = el("input", { class: "input", value: displayName(rva, origName), spellcheck: "false" });
    pop.appendChild(input);
    document.body.appendChild(pop);
    var px = Math.min(x || 200, window.innerWidth - 300), py = Math.min(y || 200, window.innerHeight - 90);
    pop.style.left = px + "px"; pop.style.top = py + "px";
    input.focus(); input.select();
    function done(save) {
      if (save) {
        var v = input.value.trim();
        if (!v || v === origName) renameMap.delete(Number(rva));
        else renameMap.set(Number(rva), v);
        saveRenames();
        if (symByName && origName) symByName.set((v || origName).toLowerCase(), rva);
        refreshAll();
        toast(v && v !== origName ? "renamed to" : "name reset", v && v !== origName ? v : "");
      }
      pop.remove();
    }
    input.addEventListener("keydown", function (e) {
      e.stopPropagation();
      if (e.key === "Enter") { e.preventDefault(); done(true); }
      else if (e.key === "Escape") { e.preventDefault(); done(false); }
    });
    input.addEventListener("blur", function () { done(false); });
  }
  function renameAtCursor() {
    var r = cursorRow(); var rva = r && r.rva != null ? r.rva : selectedFnRva;
    var f = rva != null ? funcAt(rva) : null;
    if (!f) { flashLoc("no function here"); return; }
    openRename(f.rva, f.name, window.innerWidth / 2 - 140, 160);
  }

  // ---- command palette (Ctrl+P / Ctrl+K) --------------------------------
  function paletteItems() {
    var out = [];
    funcs.forEach(function (f) { out.push({ kind: "FUNC", name: displayName(f.rva, f.name), rva: f.rva, go: function () { selectedFnRva = f.rva; decompFollow(f.rva); jumpToRva(f.rva); loadXrefs(f.rva, displayName(f.rva, f.name)); } }); });
    exports.forEach(function (e2) { out.push({ kind: "EXP", name: displayName(e2.rva, e2.name), rva: e2.rva, go: function () { jumpToRva(e2.rva); } }); });
    imports.forEach(function (im) { out.push({ kind: "IMP", name: im.name, rva: im.rva, go: function () { loadXrefs(im.rva, im.name, true); } }); });
    strings.forEach(function (s) { out.push({ kind: "STR", name: '"' + s.value + '"', rva: s.rva, go: function () { loadXrefs(s.rva, '"' + s.value + '"', true); } }); });
    segs.forEach(function (sg) { out.push({ kind: "SEG", name: sg.name, rva: sg.rva, go: function () { jumpToRva(sg.rva); } }); });
    return out;
  }
  function fuzzy(q, s) {
    q = q.toLowerCase(); s = s.toLowerCase(); var qi = 0, score = 0, run = 0, lastHit = -2, marks = [];
    for (var i = 0; i < s.length && qi < q.length; i++) {
      if (s[i] === q[qi]) { marks.push(i); score += (i === lastHit + 1) ? (run += 3) : (run = 1); if (i === 0 || /[^a-z0-9]/.test(s[i - 1])) score += 4; lastHit = i; qi++; }
    }
    return qi === q.length ? { score: score - s.length * 0.02, marks: marks } : null;
  }
  function openPalette() {
    if ($("palette-overlay")) { closePalette(); return; }
    var all = paletteItems();
    var overlay = el("div", { id: "palette-overlay" });
    var box = el("div", { class: "pal-box" });
    var input = el("input", { class: "pal-input", placeholder: "Jump to function, string, import, address…  (type 0x… for an address)", spellcheck: "false" });
    box.appendChild(el("div", { class: "pal-inputwrap" }, [el("span", { class: "pal-kind", text: "GO" }), input]));
    var list = el("div", { class: "pal-list" });
    box.appendChild(list);
    box.appendChild(el("div", { class: "pal-foot" }, [
      el("span", {}, [el("b", { text: "↑↓" }), document.createTextNode(" navigate")]),
      el("span", {}, [el("b", { text: "↵" }), document.createTextNode(" jump")]),
      el("span", {}, [el("b", { text: "esc" }), document.createTextNode(" close")])
    ]));
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    input.focus();
    var shown = [], active = 0;
    function render() {
      var q = input.value.trim();
      var res;
      if (/^0x?[0-9a-f]+$/i.test(q)) {
        res = [{ kind: "ADDR", name: "Go to " + q, rva: parseInt(q.replace(/^0x/i, ""), 16), go: function () { jumpToRva(parseInt(q.replace(/^0x/i, ""), 16)); } }];
      } else if (!q) {
        res = all.slice(0, 60);
      } else {
        res = [];
        for (var i = 0; i < all.length; i++) { var f = fuzzy(q, all[i].name); if (f) { res.push(all[i]); all[i]._s = f.score; } }
        res.sort(function (a, b) { return b._s - a._s; });
        res = res.slice(0, 60);
      }
      shown = res; active = 0; paint();
    }
    function paint() {
      clear(list);
      if (!shown.length) { list.appendChild(el("div", { class: "pal-empty", text: "No matches" })); return; }
      shown.forEach(function (it, i) {
        var row = el("div", { class: "pal-item" + (i === active ? " active" : ""), onmousemove: function () { if (active !== i) { active = i; paint(); } }, onmousedown: function (e) { e.preventDefault(); choose(i); } }, [
          el("span", { class: "pal-badge", text: it.kind }),
          el("span", { class: "pal-name", text: it.name }),
          el("span", { class: "pal-addr", text: it.rva != null ? fmtAddr(it.rva) : "" })
        ]);
        list.appendChild(row);
      });
      var act = list.children[active]; if (act && act.scrollIntoView) act.scrollIntoView({ block: "nearest" });
    }
    function choose(i) { var it = shown[i]; closePalette(); if (it) it.go(); }
    input.addEventListener("input", render);
    input.addEventListener("keydown", function (e) {
      e.stopPropagation();
      if (e.key === "ArrowDown") { e.preventDefault(); active = Math.min(shown.length - 1, active + 1); paint(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); active = Math.max(0, active - 1); paint(); }
      else if (e.key === "Enter") { e.preventDefault(); choose(active); }
      else if (e.key === "Escape") { e.preventDefault(); closePalette(); }
    });
    overlay.addEventListener("mousedown", function (e) { if (e.target === overlay) closePalette(); });
    render();
  }
  function closePalette() { var o = $("palette-overlay"); if (o) o.remove(); }

  // ---- find in pseudocode (Ctrl+F) --------------------------------------
  var findState = null;
  function openFind() {
    if (!decompIsOpen()) { decompileCurrent(); if (!decompIsOpen()) return; }
    var existing = document.querySelector(".find-bar");
    if (existing) { existing.querySelector("input").focus(); existing.querySelector("input").select(); return; }
    var bar = el("div", { class: "find-bar" });
    var input = el("input", { placeholder: "find in pseudocode", spellcheck: "false" });
    var count = el("span", { class: "find-count", text: "" });
    var prev = el("button", { class: "find-btn", title: "Previous (Shift+Enter)", text: "‹" });
    var next = el("button", { class: "find-btn", title: "Next (Enter)", text: "›" });
    var close = el("button", { class: "find-btn", title: "Close (Esc)", text: "✕" });
    bar.appendChild(input); bar.appendChild(count); bar.appendChild(prev); bar.appendChild(next); bar.appendChild(close);
    $("decomp-overlay").appendChild(bar);
    input.focus();
    findState = { hits: [], cur: -1 };
    function run() {
      var q = input.value;
      $("decomp-code").innerHTML = highlightPseudocode(decompRawText);
      findState.hits = []; findState.cur = -1;
      if (!q) { count.textContent = ""; return; }
      var hay = decompRawText, ql = q.toLowerCase(), hl = hay.toLowerCase(), idx = 0, positions = [];
      while ((idx = hl.indexOf(ql, idx)) >= 0) { positions.push(idx); idx += ql.length || 1; }
      if (!positions.length) { count.textContent = "0/0"; return; }
      // rebuild with marks by walking the raw text (highlight overrides syntax for hits)
      var html = "", last = 0;
      positions.forEach(function (p, i) {
        html += highlightPseudocode(hay.slice(last, p));
        html += '<span class="find-hit" data-hit="' + i + '">' + DSUtil.escapeHtml(hay.substr(p, q.length)) + '</span>';
        last = p + q.length;
      });
      html += highlightPseudocode(hay.slice(last));
      $("decomp-code").innerHTML = html;
      findState.hits = Array.prototype.slice.call($("decomp-code").querySelectorAll(".find-hit"));
      step(1);
    }
    function step(dir) {
      if (!findState.hits.length) return;
      if (findState.cur >= 0) findState.hits[findState.cur].classList.remove("find-cur");
      findState.cur = (findState.cur + dir + findState.hits.length) % findState.hits.length;
      var h = findState.hits[findState.cur]; h.classList.add("find-cur");
      if (h.scrollIntoView) h.scrollIntoView({ block: "center" });
      count.textContent = (findState.cur + 1) + "/" + findState.hits.length;
    }
    function closeFind() { bar.remove(); findState = null; $("decomp-code").innerHTML = highlightPseudocode(decompRawText); }
    input.addEventListener("input", run);
    input.addEventListener("keydown", function (e) {
      e.stopPropagation();
      if (e.key === "Enter") { e.preventDefault(); e.shiftKey ? step(-1) : step(1); }
      else if (e.key === "Escape") { e.preventDefault(); closeFind(); }
    });
    next.addEventListener("mousedown", function (e) { e.preventDefault(); step(1); });
    prev.addEventListener("mousedown", function (e) { e.preventDefault(); step(-1); });
    close.addEventListener("mousedown", function (e) { e.preventDefault(); closeFind(); });
  }

  // ---- keyboard ---------------------------------------------------------
  function wireKeyboard() {
    document.addEventListener("keydown", function (e) {
      var mod = e.ctrlKey || e.metaKey;
      // command palette + find work even while focused in their own inputs
      if (mod && (e.key === "p" || e.key === "P" || e.key === "k" || e.key === "K")) { e.preventDefault(); openPalette(); return; }
      if (mod && (e.key === "f" || e.key === "F")) { e.preventDefault(); openFind(); return; }

      if (e.key === "Escape") {
        if ($("palette-overlay")) { closePalette(); return; }
        if ($("ctx-menu")) { closeContextMenu(); return; }
        if (document.querySelector(".find-bar")) { document.querySelector(".find-bar .find-btn:last-child").dispatchEvent(new MouseEvent("mousedown")); return; }
        if (document.querySelector(".rename-pop")) { document.querySelector(".rename-pop").remove(); return; }
        if (hlToken) { hlToken = ""; repaintListing(); return; }
        if (!$("decomp-overlay").hidden) { setDecompOpen(false); return; }
        if (!$("help-overlay").hidden) { $("help-overlay").hidden = true; return; }
        var ge = document.querySelector(".goto-pop"); if (ge) { ge.remove(); return; }
        if (selected.size) { selected = new Set(); repaintListing(); return; }
      }
      if (isTyping()) return;
      if (finished === false) return;

      switch (e.key) {
        case "ArrowDown": case "j": e.preventDefault(); moveCursor(1, e.shiftKey); break;
        case "ArrowUp": case "k": e.preventDefault(); moveCursor(-1, e.shiftKey); break;
        case "PageDown": e.preventDefault(); moveCursor(24, e.shiftKey); break;
        case "PageUp": e.preventDefault(); moveCursor(-24, e.shiftKey); break;
        case "Home": e.preventDefault(); selectOne(0); if (disVList) disVList.scrollToIndex(0); break;
        case "End": e.preventDefault(); selectOne(listingLen - 1); if (disVList) disVList.scrollToIndex(listingLen - 1); break;
        case "Enter": e.preventDefault(); followAtCursor(); break;
        case ";": case ":": e.preventDefault(); editComment(); break;
        case "m": case "M": e.preventDefault(); toggleMark(); break;
        case "]": e.preventDefault(); jumpMark(1); break;
        case "[": e.preventDefault(); jumpMark(-1); break;
        case "n": case "N": e.preventDefault(); renameAtCursor(); break;
        case "x": case "X": e.preventDefault(); xrefAtCursor(); break;
        case "g": e.preventDefault(); openGoto(); break;
        case "G": e.preventDefault(); openPalette(); break;
        case "F5": e.preventDefault(); toggleDecompile(); break;
        case "/": e.preventDefault(); $("fn-filter").focus(); break;
        case "?": e.preventDefault(); toggleHelp(); break;
        case "Backspace": e.preventDefault(); goBack(); break;
        case "ArrowLeft": if (e.altKey) { e.preventDefault(); goBack(); } break;
        case "ArrowRight": if (e.altKey) { e.preventDefault(); goFwd(); } break;
        case "c": case "C":
          if (mod) { if (hasTextSelection()) { copyText(String(window.getSelection())); toast("copied selection"); } else { copySelection(e.shiftKey); } e.preventDefault(); }
          break;
        case "Escape": break;
      }
    });
  }

  // follow the reference on the cursor row (Enter), else decompile it.
  function followAtCursor() {
    var r = cursorRow();
    if (r && r.ref_target != null) { pushHistory(); jumpToRva(Number(r.ref_target)); return; }
    decompileCurrent();
  }
  function xrefAtCursor() {
    var r = cursorRow(); var rva = r && r.rva != null ? r.rva : null; if (rva == null) return;
    var f = funcAt(rva);
    loadXrefs(rva, f ? displayName(f.rva, f.name) : fmtAddr(rva));
  }

  // ---- help -------------------------------------------------------------
  function toggleHelp() { var o = $("help-overlay"); o.hidden = !o.hidden; }
  function buildHelp() {
    var rows = [
      ["sec", "Navigate"],
      ["Ctrl+P / Ctrl+K", "command palette — jump to anything"],
      ["g", "goto address"], ["G", "command palette"],
      ["Enter / dblclick", "follow reference under cursor"],
      ["click operand", "follow reference"], ["alt+← / alt+→", "back / forward"],
      ["backspace", "jump back"], ["] / [", "next / prev mark"],
      ["sec", "Select & copy"],
      ["drag", "select text (real selection)"], ["click", "select line + highlight token"],
      ["shift+click / shift+↑↓", "extend selection"], ["ctrl+click", "toggle line"],
      ["j / k / ↑ / ↓", "move cursor"], ["Home / End", "top / bottom"],
      ["Ctrl+C", "copy selection / text"], ["Ctrl+Shift+C", "copy address(es)"],
      ["sec", "Annotate & analyze"],
      ["N", "rename function"], [";", "add / edit comment"], ["M", "toggle mark"],
      ["X", "cross-references"], ["F5", "decompile function"],
      ["Ctrl+F", "find in pseudocode"], ["/", "filter sidebar"],
      ["click token", "highlight all occurrences"], ["esc", "clear / close"], ["?", "this help"]
    ];
    var g = clear($("help-grid"));
    rows.forEach(function (r) {
      if (r[0] === "sec") { g.appendChild(el("div", { class: "sec", text: r[1] })); return; }
      g.appendChild(el("kbd", { text: r[0] }));
      g.appendChild(el("span", { class: "d", text: r[1] }));
    });
    $("help-overlay").addEventListener("click", function (e) { if (e.target === $("help-overlay")) $("help-overlay").hidden = true; });
  }
})();
