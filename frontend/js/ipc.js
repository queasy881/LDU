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

  /* NO MOCK HOST.
     There used to be one here: ~80 lines that fabricated functions, strings,
     imports and disassembly whenever the page was opened outside the app. It
     made the UI look alive in a browser tab, which is exactly the problem --
     a pane full of invented data is indistinguishable from a pane showing a
     real binary, so a wiring bug reads as working software. Off-host now
     REJECTS, loudly and once per command. */
  function invoke(cmd, params) {
    if (HOST) return hostSend(cmd, params);
    return Promise.reject(new Error(
      "no analysis host: '" + cmd + "' needs the DisasmStudio app (this page shows real data only)"));
  }

  window.DS = {
    invoke: invoke,
    on: function (ev, fn) { if (!listeners.has(ev)) listeners.set(ev, []); listeners.get(ev).push(fn); },
    isHost: HOST
  };
})();
