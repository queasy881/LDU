/* ============================================================================
   ipc.js — transport between the frontend and the Rust/wry host.
   Contract (unchanged, this is the ONE thing the rebuild must preserve):
     JS  -> host : window.ipc.postMessage(JSON.stringify({ id, cmd, ...params }))
     host -> JS  : window.__IPC_EVENT__(obj)
                     reply : { id, ok:true, data } | { id, ok:false, error }
                     push  : { event, ... }
   Public API:  DS.invoke(cmd, params) -> Promise<data>
                DS.on(event, fn)        subscribe to a push event
   A small MOCK host provides stub data when opened in a plain browser.
   ============================================================================ */
(function () {
  "use strict";
  var pending = new Map();
  var nextId = 1;
  var listeners = new Map();     // event name -> [fn]
  var HOST = !!(window.ipc && typeof window.ipc.postMessage === "function");

  function emit(ev, obj) {
    var l = listeners.get(ev); if (!l) return;
    l.slice().forEach(function (fn) { try { fn(obj); } catch (e) { console.error(e); } });
  }

  window.__IPC_EVENT__ = function (obj) {
    if (typeof obj === "string") { try { obj = JSON.parse(obj); } catch (e) { return; } }
    if (!obj || typeof obj !== "object") return;
    if (obj.id != null && pending.has(obj.id)) {
      var p = pending.get(obj.id); pending.delete(obj.id);
      if (obj.ok === false) p.reject(new Error(obj.error || "ipc error"));
      else p.resolve(obj.data);
      return;
    }
    if (obj.event) emit(obj.event, obj);
  };

  function hostSend(cmd, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending.set(id, { resolve: resolve, reject: reject });
      var msg = { id: id, cmd: cmd };
      if (params) for (var k in params) if (Object.prototype.hasOwnProperty.call(params, k)) msg[k] = params[k];
      try { window.ipc.postMessage(JSON.stringify(msg)); }
      catch (e) { pending.delete(id); reject(e); }
    });
  }

  /* --------------------------------------------------------------------------
     MOCK host: enough stub data to preview the whole UI in a browser tab.
     -------------------------------------------------------------------------- */
  var Mock = (function () {
    function h(v, n) { v = (v >>> 0).toString(16); while (v.length < n) v = "0" + v; return v; }
    var MN = ["push","mov","lea","call","test","je","jne","cmp","add","sub","xor","ret","and","or","shr","shl","movzx","jmp"];
    var funcs = [], insns = [], strings = [], imports = [], exports = [];
    var base = 0x140001000;
    (function build() {
      var rva = 0x1000, idx = 0;
      for (var f = 0; f < 220; f++) {
        var sz = 24 + ((f * 37) % 480), start = rva, blocks = 1 + (f % 6);
        funcs.push({ rva: rva, name: f % 5 === 0 ? "sub_" + h(rva, 6) : (["init_ctx","parse_hdr","hash_block","xf_apply","vm_step","emit_row","scan_pool","lock_acquire"][f % 8]) + "_" + f, size: sz, block_count: blocks, call_count: (f * 3) % 9 });
        var end = rva + sz;
        while (rva < end) {
          var m = MN[(idx * 7 + rva) % MN.length];
          var rt = m[0] === "j" ? (m === "jmp" ? 2 : 4) : (m === "call" ? 1 : 0);
          var tgt = rt === 1 ? funcs[(idx) % Math.max(1, funcs.length)].rva : (rt ? (rva + 8) : 0);
          insns.push({ index: idx, rva: rva, bytes: h((idx * 2654435761) >>> 0, 6), mnemonic: m, operands: mockOps(m, rva), ref_target: tgt, ref_type: rt });
          rva += 2 + (idx % 6); idx++;
        }
        rva = end + (8 - (end % 8));
      }
      for (var s = 0; s < 60; s++) strings.push({ rva: 0x30000 + s * 24, value: ["[cfg] loaded %d rows","GENERIC_WRITE","kernel32.dll","\\Device\\Null","%s: %llx","VALORANT","init failed"][s % 7] + " #" + s, kind: 0 });
      ["HeapAlloc","VirtualProtect","CreateFileW","RtlEnterCriticalSection","GetProcAddress"].forEach(function (n, i) { imports.push({ rva: 0x9000 + i * 8, name: n }); });
      funcs.slice(0, 8).forEach(function (f) { exports.push({ rva: f.rva, name: f.name }); });
    })();
    function mockOps(m, rva) {
      var regs = ["rax","rcx","rdx","rbx","rsi","rdi","r8","r9"];
      if (m === "call" || m === "jmp") return "0x" + (rva + 64).toString(16);
      if (m[0] === "j") return "0x" + (rva + 24).toString(16);
      if (m === "mov" || m === "lea") return regs[rva % 8] + ", [" + regs[(rva + 3) % 8] + "+0x" + ((rva % 64)).toString(16) + "]";
      if (m === "cmp" || m === "test" || m === "add" || m === "sub" || m === "xor") return regs[rva % 8] + ", 0x" + ((rva * 7) % 4096).toString(16);
      if (m === "push" || m === "ret") return m === "ret" ? "" : regs[rva % 8];
      return regs[rva % 8];
    }
    var rows = null;
    function listing() {
      if (rows) return rows;
      rows = []; var curSeg = null;
      rows.push({ kind: "segment", name: ".text", rva: 0x1000, size: 0x40000, flags: 0x60000020, r: true, w: false, x: true });
      var fi = 0;
      insns.forEach(function (ins) {
        while (fi < funcs.length && funcs[fi].rva <= ins.rva) {
          if (funcs[fi].rva === ins.rva) rows.push({ kind: "func", rva: funcs[fi].rva, name: funcs[fi].name, size: funcs[fi].size, block_count: funcs[fi].block_count });
          fi++;
        }
        rows.push(Object.assign({ kind: "insn" }, ins));
      });
      return rows;
    }
    function decompile(rva) {
      var f = funcs.find(function (x) { return x.rva === rva; }) || funcs[0];
      return "#include <stdint.h>\n/* " + f.name + " @ 0x" + f.rva.toString(16) + "  size=" + f.size + " */\n/* confidence: HIGH */\nint64_t " + f.name + "(int64_t a1, int64_t a2) {\n    int32_t v1 = 0;\n    if (!a1) return 0;\n    for (int32_t i = 0; i < (int32_t)a2; i++) {\n        v1 += *(int32_t*)((char*)a1 + i * 4);\n        if (v1 > 0x1000) break;\n    }\n    return v1;\n}\n";
    }
    return {
      handle: function (cmd, p) {
        var L = listing();
        switch (cmd) {
          case "get_session_info": return { name: "sample.dll", path: "C:/bin/sample.dll", project: "demo" };
          case "get_binary_meta":  return { arch: "x64", base: base, entry: 0x1200, is_dll: true };
          case "get_functions":    return funcs;
          case "get_segments":     return [{ name: ".text", rva: 0x1000, size: 0x40000, flags: 0x60000020, r: true, w: false, x: true }, { name: ".rdata", rva: 0x41000, size: 0x9000, flags: 0x40000040, r: true, w: false, x: false }, { name: ".data", rva: 0x4a000, size: 0x3000, flags: 0xc0000040, r: true, w: true, x: false }];
          case "get_exports":      return exports;
          case "get_imports":      return imports;
          case "get_strings":      return strings;
          case "get_listing_len":  return { len: L.length };
          case "get_disassembly":  return L.slice(p.start, p.start + p.count);
          case "get_row_for_rva":  { var i = L.findIndex(function (r) { return r.rva >= p.rva; }); return { index: i }; }
          case "get_xrefs_to":     return funcs.slice(0, 3).map(function (f) { return { from_rva: f.rva + 12, to_rva: p.rva, type: 1 }; });
          case "get_pseudocode":   return { code: decompile(p.rva) + (p.sm ? "\n/* (state-machine form; DS_FORCE_SM) */\n" : "") };
          case "get_comments":     return {};
          case "get_marks":        return [];
          case "toggle_mark":      return { ok: true };
          case "set_comment":      return { ok: true };
          case "ping":             return { pong: true };
          default:                 return null;
        }
      }
    };
  })();

  function invoke(cmd, params) {
    if (HOST) return hostSend(cmd, params);
    return new Promise(function (res) { setTimeout(function () { res(Mock.handle(cmd, params || {})); }, 8); });
  }

  window.DS = {
    invoke: invoke,
    on: function (ev, fn) { if (!listeners.has(ev)) listeners.set(ev, []); listeners.get(ev).push(fn); },
    isHost: HOST
  };
})();
