/* ============================================================================
   ipc.js — transport layer between the frontend and the Rust/wry host.

   HOST present (window.ipc.postMessage):
     JS  -> host: window.ipc.postMessage(JSON.stringify({id, cmd, ...params}))
     host -> JS : window.__IPC_EVENT__(obj) where obj is one of
                    RESPONSE {id, ok:true,  data}
                    RESPONSE {id, ok:false, error}
                    PUSH     {event, ...fields}      (no id)

   HOST absent (plain browser preview): a MOCK answers every command with
   plausible stub data so the entire UI is exercisable offline.

   Public surface (consumed by app.js):
     DSIPC.sendRaw(cmd, params) -> Promise<data>
     window.__IPC_EVENT__(obj)            (installed here)
     DSIPC.onPush(fn) / DSIPC._setPush(fn) — bridge to DS event bus
   ========================================================================== */
(function () {
  "use strict";

  var HOST = !!(window.ipc && typeof window.ipc.postMessage === "function");

  // pending host requests: id -> {resolve, reject}
  var pending = new Map();
  var nextId = 1;

  // push sink — app.js installs the real one via _setPush(); until then queue.
  var pushSink = null;
  var pushQueue = [];
  function emitPush(obj) {
    if (pushSink) pushSink(obj.event, obj);
    else pushQueue.push(obj);
  }
  function setPush(fn) {
    pushSink = fn;
    if (pushQueue.length) {
      var q = pushQueue; pushQueue = [];
      for (var i = 0; i < q.length; i++) fn(q[i].event, q[i]);
    }
  }

  // ---- the dispatcher the host calls into -------------------------------
  window.__IPC_EVENT__ = function (obj) {
    if (typeof obj === "string") {
      try { obj = JSON.parse(obj); } catch (e) { return; }
    }
    if (!obj || typeof obj !== "object") return;
    if (obj.id != null && pending.has(obj.id)) {
      var p = pending.get(obj.id);
      pending.delete(obj.id);
      if (obj.ok === false) p.reject(new Error(obj.error || "ipc error"));
      else p.resolve(obj.data);
      return;
    }
    if (obj.event) { emitPush(obj); return; }
    // stray response with no matching pending id — ignore.
  };

  // ---- real host send ----------------------------------------------------
  function hostSend(cmd, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending.set(id, { resolve: resolve, reject: reject });
      var msg = { id: id, cmd: cmd };
      if (params) for (var k in params) if (Object.prototype.hasOwnProperty.call(params, k)) msg[k] = params[k];
      try {
        window.ipc.postMessage(JSON.stringify(msg));
      } catch (e) {
        pending.delete(id);
        reject(e);
      }
    });
  }

  // ======================================================================
  //  MOCK host — realistic stub data for browser preview.
  // ======================================================================
  var Mock = (function () {
    var BASE = 0x140000000;

    function h2(v) { v &= 0xff; return (v < 16 ? "0" : "") + v.toString(16); }

    // --- segments ---
    var segs = [
      { name: ".text",  rva: 0x1000,  size: 0x9000, flags: 1 | 4 },
      { name: ".rdata", rva: 0xA000,  size: 0x3000, flags: 1 },
      { name: ".data",  rva: 0xD000,  size: 0x2000, flags: 1 | 2 },
      { name: ".pdata", rva: 0xF000,  size: 0x1000, flags: 1 }
    ];

    // --- functions (~60) inside .text ---
    var funcs = [];
    var FN_COUNT = 60;
    (function () {
      var rva = 0x1000;
      var names = ["start", "DllMain", "sub_", "WinMainCRTStartup", "__security_init_cookie",
        "memcpy", "memset", "alloc_pool", "free_pool", "parse_header",
        "validate_input", "hash_block", "decrypt_stage", "thread_proc", "wnd_proc"];
      for (var i = 0; i < FN_COUNT; i++) {
        var size = 0x40 + ((i * 53) % 0x180);
        var nm;
        if (i < 4) nm = names[i];
        else if (i % 7 === 0 && (i / 7) < names.length - 5) nm = names[5 + (i / 7 | 0)];
        else nm = "sub_" + (BASE + rva).toString(16);
        funcs.push({
          rva: rva, name: nm, size: size,
          block_count: 1 + ((i * 3) % 9),
          call_count: (i * 2) % 11
        });
        rva += size + (i % 3) * 4;
      }
    })();

    // --- instructions across all functions ---
    // Build a flat instruction list; each func gets size/~4 insns.
    var insns = [];
    var rvaToInsn = new Map();
    var MNEMS = [
      ["push", "rbp", 0, 0],
      ["mov", "rbp, rsp", 0, 0],
      ["sub", "rsp, 0x20", 0, 0],
      ["mov", "rax, [rcx+0x10]", 3, 0],
      ["test", "rax, rax", 0, 0],
      ["je", "$T", 4, 0],
      ["call", "$C", 1, 0],
      ["lea", "rcx, [$D]", 3, 0],
      ["jmp", "$J", 2, 0],
      ["xor", "eax, eax", 0, 0],
      ["add", "rsp, 0x20", 0, 0],
      ["pop", "rbp", 0, 0],
      ["ret", "", 0, 0],
      ["cmp", "dword ptr [rbp-0x4], 0", 0, 0],
      ["nop", "", 0, 0]
    ];
    (function () {
      for (var f = 0; f < funcs.length; f++) {
        var fn = funcs[f];
        var rva = fn.rva;
        var endrva = fn.rva + fn.size;
        var step = 0;
        while (rva < endrva) {
          var pick = MNEMS[step % MNEMS.length];
          var mnem = pick[0];
          var ops = pick[1];
          var reftype = pick[2];
          var reftarget = null;
          // produce a few bytes deterministically
          var len = 1 + ((rva * 7 + step) % 5);
          var bytes = [];
          for (var b = 0; b < len; b++) bytes.push((rva * 13 + step * 31 + b * 7) & 0xff);

          if (reftype === 1) { // call -> some function start
            var tf = funcs[(f + 1 + step) % funcs.length];
            reftarget = tf.rva;
            ops = "sub_" + (BASE + tf.rva).toString(16);
          } else if (reftype === 2) { // jmp -> within nearby
            reftarget = (rva + 0x20) < endrva ? rva + 0x20 : fn.rva;
            ops = "loc_" + (BASE + reftarget).toString(16);
          } else if (reftype === 4) { // cond branch
            reftarget = (rva + 0x10) < endrva ? rva + 0x10 : fn.rva;
            ops = "loc_" + (BASE + reftarget).toString(16);
          } else if (reftype === 3) { // data
            reftarget = 0xA000 + ((rva * 3) % 0x2000);
            ops = ops.replace("$D", "rip+0x" + (reftarget).toString(16));
          }

          var ins = {
            index: insns.length,
            rva: rva,
            bytes: bytes.map(h2).join(" "),
            mnemonic: mnem,
            operands: ops,
            ref_target: reftarget,
            ref_type: reftype
          };
          insns.push(ins);
          rvaToInsn.set(rva, ins.index);
          rva += len;
          step++;
        }
      }
    })();

    // --- listing rows: walk insns; emit seg banners + func banners ---
    var rows = []; // each: {kind, ...}
    (function () {
      var segByRva = new Map(); segs.forEach(function (s) { segByRva.set(s.rva, s); });
      var fnByRva = new Map(); funcs.forEach(function (f) { fnByRva.set(f.rva, f); });
      for (var i = 0; i < insns.length; i++) {
        var ins = insns[i];
        if (segByRva.has(ins.rva)) {
          var s = segByRva.get(ins.rva);
          rows.push({ kind: "segment", name: s.name, rva: s.rva, size: s.size, flags: s.flags,
            r: !!(s.flags & 1), w: !!(s.flags & 2), x: !!(s.flags & 4) });
        }
        if (fnByRva.has(ins.rva)) {
          var fn = fnByRva.get(ins.rva);
          rows.push({ kind: "func", rva: fn.rva, name: fn.name, size: fn.size, block_count: fn.block_count });
        }
        rows.push({ kind: "insn", _i: i });
      }
    })();

    // listing-index per rva (prefer func banner index for a func start)
    var rvaToRow = new Map();
    (function () {
      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        if (row.kind === "insn") {
          var ins = insns[row._i];
          if (!rvaToRow.has(ins.rva)) rvaToRow.set(ins.rva, r);
        } else if (row.kind === "func") {
          rvaToRow.set(row.rva, r); // overrides — prefer banner
        }
      }
    })();

    // --- xrefs (reverse index): for each call/jmp/cond, record edge to target ---
    var xrefsTo = new Map(); // to_rva -> [ {from_rva,to_rva,type} ]
    (function () {
      for (var i = 0; i < insns.length; i++) {
        var ins = insns[i];
        if (ins.ref_target != null && ins.ref_type !== 0) {
          var t = ins.ref_target;
          if (!xrefsTo.has(t)) xrefsTo.set(t, []);
          // type 1 call,2 jmp,3 data — map cond-branch(4) to jmp(2)
          var kind = ins.ref_type === 4 ? 2 : ins.ref_type;
          xrefsTo.get(t).push({ from_rva: ins.rva, to_rva: t, type: kind });
        }
      }
    })();

    // --- projects (persisted in localStorage for the mock) ---
    var LS_KEY = "ds_mock_projects";
    function loadProjects() {
      try {
        var raw = localStorage.getItem(LS_KEY);
        if (raw) return JSON.parse(raw);
      } catch (e) {}
      return [
        { name: "kernel32.dll", path: "C:\\Windows\\System32\\kernel32.dll", last_opened: "3", arch: "x64" },
        { name: "ntdll.dll", path: "C:\\Windows\\System32\\ntdll.dll", last_opened: "2", arch: "x64" },
        { name: "demo.exe", path: "C:\\samples\\demo.exe", last_opened: "1", arch: "x64" }
      ];
    }
    function saveProjects(list) {
      try { localStorage.setItem(LS_KEY, JSON.stringify(list)); } catch (e) {}
    }
    var openCounter = 100;

    var meta = {
      name: "demo.exe",
      path: "C:\\samples\\demo.exe",
      format: "PE32+",
      arch: "x64",
      base: BASE,
      entry: 0x1000,
      image_size: 0x10000,
      segment_count: segs.length,
      function_count: funcs.length,
      instruction_count: insns.length,
      listing_len: rows.length
    };

    function nearestRowAtOrAfter(rva) {
      if (rvaToRow.has(rva)) return rvaToRow.get(rva);
      // find smallest insn rva >= rva
      var best = -1, bestRva = Infinity;
      for (var i = 0; i < insns.length; i++) {
        if (insns[i].rva >= rva && insns[i].rva < bestRva) {
          bestRva = insns[i].rva; best = i;
        }
      }
      if (best < 0) return -1;
      return rvaToRow.has(insns[best].rva) ? rvaToRow.get(insns[best].rva) : -1;
    }

    // simulated analysis push timeline
    var analysisTimer = null;
    function startAnalysis() {
      cancelAnalysis();
      var stages = [
        { stage: "Parsing binary", from: 0, to: 20 },
        { stage: "Building CFG", from: 20, to: 50 },
        { stage: "Recovering symbols", from: 50, to: 70 },
        { stage: "Indexing cross-references", from: 70, to: 90 },
        { stage: "Finalizing", from: 90, to: 99 }
      ];
      var si = 0, pct = 0;
      analysisTimer = setInterval(function () {
        if (si >= stages.length) {
          clearInterval(analysisTimer); analysisTimer = null;
          emitPush({ event: "analysis_done" });
          return;
        }
        var st = stages[si];
        if (pct < st.from) pct = st.from;
        pct += 3 + Math.floor(Math.random() * 6);
        if (pct >= st.to) { pct = st.to; si++; }
        emitPush({ event: "analysis_progress", stage: st.stage, pct: pct });
      }, 90);
    }
    function cancelAnalysis() {
      if (analysisTimer) { clearInterval(analysisTimer); analysisTimer = null; }
    }

    function handle(cmd, params) {
      params = params || {};
      switch (cmd) {
        case "open_file_dialog":
          // browser can't open a native dialog; return a fake path.
          return { path: "C:\\samples\\selected_" + Date.now() + ".exe" };

        case "get_projects_list":
          return loadProjects().slice().sort(function (a, b) {
            return (parseInt(b.last_opened, 10) || 0) - (parseInt(a.last_opened, 10) || 0);
          });

        case "save_project_meta": {
          var list = loadProjects();
          var found = false;
          for (var i = 0; i < list.length; i++) {
            if (list[i].path === params.path) {
              list[i].name = params.name; list[i].arch = params.arch;
              list[i].last_opened = String(++openCounter); found = true; break;
            }
          }
          if (!found) {
            list.push({ name: params.name, path: params.path, arch: params.arch || "x64",
              last_opened: String(++openCounter) });
          }
          saveProjects(list);
          return { ok: true };
        }

        case "remove_project": {
          var list2 = loadProjects().filter(function (p) { return p.path !== params.path; });
          saveProjects(list2);
          return { ok: true };
        }

        case "open_project":
          meta.path = params.path || meta.path;
          setTimeout(startAnalysis, 60);
          return { ok: true };

        case "cancel_analysis":
          cancelAnalysis();
          return { ok: true };

        case "get_binary_meta":
          return meta;

        case "get_functions":
          return funcs.map(function (f) {
            return { rva: f.rva, name: f.name, size: f.size,
              block_count: f.block_count, call_count: f.call_count };
          });

        case "get_segments":
          return segs.map(function (s) {
            return { name: s.name, rva: s.rva, size: s.size, flags: s.flags,
              r: !!(s.flags & 1), w: !!(s.flags & 2), x: !!(s.flags & 4) };
          });

        case "get_listing_len":
          return { len: rows.length };

        case "get_disassembly": {
          var start = params.start | 0, count = params.count | 0;
          var out = [];
          for (var i = start; i < start + count && i < rows.length; i++) {
            var row = rows[i];
            if (row.kind === "insn") {
              var ins = insns[row._i];
              out.push({ kind: "insn", index: ins.index, rva: ins.rva, bytes: ins.bytes,
                mnemonic: ins.mnemonic, operands: ins.operands,
                ref_target: ins.ref_target, ref_type: ins.ref_type });
            } else {
              out.push(row);
            }
          }
          return out;
        }

        case "get_row_for_rva":
          return { index: nearestRowAtOrAfter(params.rva >>> 0 === params.rva ? params.rva : params.rva) };

        case "get_xrefs_to": {
          var arr = xrefsTo.get(params.rva) || [];
          return arr.map(function (x) { return { from_rva: x.from_rva, to_rva: x.to_rva, type: x.type }; });
        }

        default:
          throw new Error("mock: unknown command '" + cmd + "'");
      }
    }

    return { handle: handle };
  })();

  function mockSend(cmd, params) {
    return new Promise(function (resolve, reject) {
      // async to mimic real IPC latency and keep call sites consistent
      setTimeout(function () {
        try { resolve(Mock.handle(cmd, params)); }
        catch (e) { reject(e instanceof Error ? e : new Error(String(e))); }
      }, 0);
    });
  }

  function sendRaw(cmd, params) {
    return HOST ? hostSend(cmd, params) : mockSend(cmd, params);
  }

  window.DSIPC = {
    HOST: HOST,
    sendRaw: sendRaw,
    _setPush: setPush,
    onPush: setPush
  };
})();
