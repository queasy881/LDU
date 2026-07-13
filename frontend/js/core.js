/* ============================================================================
   core.js — shared frontend core for the MULTI-WINDOW DisasmStudio app.

   Every page (launcher.html / project.html / disasm.html) loads, in order:
       js/ipc.js   -> window.DSIPC  (transport + push fan-in; sendRaw/_setPush)
       js/util.js  -> el, hex, fmtAddr, fmtBytes, debounce, clear, classToggle
     [ js/vlist.js -> window.VList  (disasm page only) ]
       js/core.js  -> window.DS     (THIS FILE)
       js/<page>.js                 (the page controller)

   This file defines the single shared namespace used by every page controller:

     window.DS = {
       invoke(cmd, params={}) -> Promise<data>   // rejects Error on {ok:false}
       on(event, fn)                             // subscribe to a host push event
       off(event, fn)                            // unsubscribe
       state: {}                                 // per-window shared scratch
       HOST:  Boolean                            // true when running in the wry host
     }

   There is NO screen router here: each OS window owns one HTML page and that
   page owns its own DOM. Push events from the host (e.g. analysis_progress,
   analysis_done, analysis_error) arrive through ipc.js and are fanned out to
   DS.on() listeners via DS._push, which is registered with DSIPC._setPush so any
   events queued before this file ran are flushed immediately.

   Robust to load order: if a page script happened to run before core.js it would
   simply reference window.DS later; core.js only needs window.DSIPC (loaded
   first via the documented <script defer> order) to exist when it runs.
   ========================================================================== */
(function () {
  "use strict";

  if (window.DS && window.DS.__core__) return; // idempotent: never double-install

  var IPC = window.DSIPC || null;

  // ---- event bus ---------------------------------------------------------
  // event name -> array of handler fns
  var bus = Object.create(null);

  function on(event, fn) {
    if (!event || typeof fn !== "function") return;
    (bus[event] || (bus[event] = [])).push(fn);
  }

  function off(event, fn) {
    var arr = bus[event];
    if (!arr) return;
    var i = arr.indexOf(fn);
    if (i >= 0) arr.splice(i, 1);
  }

  /* _push(eventName, payload) — called by ipc.js for every host PUSH.
     ipc.js invokes pushSink(obj.event, obj), so signature is (event, payload). */
  function _push(event, payload) {
    var arr = bus[event];
    if (!arr || !arr.length) return;
    var snap = arr.slice(); // copy so a handler may off() itself mid-dispatch
    for (var i = 0; i < snap.length; i++) {
      try { snap[i](payload); }
      catch (e) { if (window.console) console.error("DS push listener error", e); }
    }
  }

  // ---- invoke ------------------------------------------------------------
  /* invoke(cmd, params) -> Promise<data>. DSIPC.sendRaw already rejects with an
     Error built from {ok:false,error}; we just guard for a missing transport. */
  function invoke(cmd, params) {
    if (!IPC || typeof IPC.sendRaw !== "function") {
      return Promise.reject(new Error("DSIPC transport unavailable"));
    }
    return IPC.sendRaw(cmd, params || {});
  }

  // ---- assemble namespace ------------------------------------------------
  window.DS = {
    __core__: true,
    invoke: invoke,
    on: on,
    off: off,
    _push: _push,
    state: {},
    HOST: !!(IPC && IPC.HOST)
  };

  // Route host push events into our bus, flushing anything ipc.js queued before
  // a sink was registered.
  if (IPC && typeof IPC._setPush === "function") {
    IPC._setPush(_push);
  }
})();
