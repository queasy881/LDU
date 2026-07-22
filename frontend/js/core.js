/* ============================================================================
   core.js — shared APPLICATION UX layer for every window.
   Transport (window.DS) lives in ipc.js; DOM helpers (window.U) in util.js.
   This file adds the cross-page interaction fabric that gives the AXIOM UI its
   character, exposed as window.APP:

     APP.keymap        register global keyboard shortcuts (shown in the palette)
     APP.palette       the Ctrl+K command palette (fuzzy, keyboard-driven)
     APP.command       register a palette/keymap command
     APP.brandbar()    build the shared thin top brand strip
     APP.ready(fn)     run fn on DOMContentLoaded (or now if already loaded)

   The palette + keymap are the same everywhere, so a shortcut learned on one
   page works on the next.
   ============================================================================ */
(function () {
  "use strict";
  var U = window.U;

  /* ---- ready ------------------------------------------------------------- */
  function ready(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }

  /* ---- command registry -------------------------------------------------- */
  // { id, title, hint, keys:[..], group, run() }
  var commands = [];
  var byKey = Object.create(null);   // "ctrl+k" -> command

  function normKeys(combo) {
    return combo.toLowerCase().split("+").map(function (s) { return s.trim(); }).sort().join("+");
  }
  function command(spec) {
    if (!spec || !spec.id) return;
    commands.push(spec);
    (spec.keys || []).forEach(function (k) { byKey[normKeys(k)] = spec; });
    return spec;
  }
  function removeCommand(id) {
    commands = commands.filter(function (c) { return c.id !== id; });
    Object.keys(byKey).forEach(function (k) { if (byKey[k] && byKey[k].id === id) delete byKey[k]; });
  }

  function comboFromEvent(e) {
    var parts = [];
    if (e.ctrlKey || e.metaKey) parts.push("ctrl");
    if (e.altKey) parts.push("alt");
    if (e.shiftKey) parts.push("shift");
    var k = (e.key || "").toLowerCase();
    if (k === " ") k = "space";
    if (["control", "meta", "alt", "shift"].indexOf(k) < 0) parts.push(k);
    return parts.sort().join("+");
  }

  function isTypingTarget(t) {
    if (!t) return false;
    var tag = t.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || t.isContentEditable;
  }

  /* ---- command palette --------------------------------------------------- */
  var pal = null; // { root, input, list, items, sel, open }
  function buildPalette() {
    if (pal) return pal;
    var input = U.el("input.pal-input", { type: "text", placeholder: "Type a command…  ", spellcheck: "false", autocomplete: "off" });
    var list = U.el("div.pal-list");
    var box = U.el("div.pal-box", null, [
      U.el("div.pal-head", null, [U.el("span.pal-glyph", { text: "›_" }), input, U.el("span.kbd", { text: "esc" })]),
      list
    ]);
    var root = U.el("div.pal-scrim", null, [box]);
    root.addEventListener("mousedown", function (e) { if (e.target === root) close(); });
    document.body.appendChild(root);

    pal = { root: root, input: input, list: list, items: [], sel: 0, open: false };

    input.addEventListener("input", function () { render(input.value); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") { e.preventDefault(); commit(); }
      else if (e.key === "Escape") { e.preventDefault(); close(); }
    });
    return pal;
  }

  function score(q, s) {
    // simple subsequence fuzzy score; -1 if no match
    q = q.toLowerCase(); s = s.toLowerCase();
    if (!q) return 0;
    var qi = 0, si = 0, sc = 0, streak = 0;
    while (qi < q.length && si < s.length) {
      if (q[qi] === s[si]) { qi++; streak++; sc += 1 + streak; if (si === 0) sc += 3; }
      else streak = 0;
      si++;
    }
    return qi === q.length ? sc : -1;
  }

  function render(q) {
    var p = pal;
    var scored = commands.map(function (c) {
      var text = c.title + " " + (c.group || "") + " " + (c.hint || "");
      return { c: c, s: q ? score(q, text) : 0 };
    }).filter(function (r) { return r.s >= 0; });
    scored.sort(function (a, b) { return b.s - a.s; });
    p.items = scored.map(function (r) { return r.c; });
    p.sel = 0;
    U.clear(p.list);
    if (!p.items.length) { p.list.appendChild(U.el("div.pal-empty", { text: "No matching command" })); return; }
    p.items.forEach(function (c, i) {
      var keycap = (c.keys && c.keys[0]) ? U.el("span.pal-keys", null, prettyKeys(c.keys[0])) : null;
      var row = U.el("div.pal-item" + (i === 0 ? ".on" : ""), { onclick: function () { p.sel = i; commit(); } }, [
        U.el("div.pal-item-main", null, [
          c.group ? U.el("span.pal-group", { text: c.group }) : null,
          U.el("span.pal-title", { text: c.title })
        ]),
        keycap
      ]);
      row.dataset.i = i;
      p.list.appendChild(row);
    });
  }
  function prettyKeys(combo) {
    return combo.split("+").map(function (k) {
      k = k.trim();
      var label = ({ ctrl: "Ctrl", alt: "Alt", shift: "⇧", arrowup: "↑", arrowdown: "↓", enter: "↵", escape: "Esc", space: "Space" })[k.toLowerCase()] || k.toUpperCase();
      return U.el("kbd.kbd", { text: label });
    });
  }
  function move(d) {
    var p = pal; if (!p.items.length) return;
    p.sel = (p.sel + d + p.items.length) % p.items.length;
    U.$all(".pal-item", p.list).forEach(function (n, i) { n.classList.toggle("on", i === p.sel); });
    var cur = p.list.children[p.sel]; if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: "nearest" });
  }
  function commit() {
    var p = pal, c = p.items[p.sel]; close();
    if (c && typeof c.run === "function") { try { c.run(); } catch (e) { console.error(e); } }
  }
  function open() {
    buildPalette(); pal.open = true; pal.input.value = ""; render("");
    requestAnimationFrame(function () { pal.root.classList.add("show"); pal.input.focus(); });
  }
  function close() { if (pal) { pal.open = false; pal.root.classList.remove("show"); } }
  function toggle() { (pal && pal.open) ? close() : open(); }

  /* ---- global key dispatch ---------------------------------------------- */
  document.addEventListener("keydown", function (e) {
    var combo = comboFromEvent(e);
    if (combo === "ctrl+k" || combo === "ctrl+shift+p") { e.preventDefault(); toggle(); return; }
    if (pal && pal.open) return; // palette handles its own keys
    if (isTypingTarget(e.target) && combo.indexOf("ctrl") < 0 && combo.indexOf("alt") < 0) return;
    var c = byKey[combo];
    if (c && typeof c.run === "function") { e.preventDefault(); c.run(); }
  });

  /* ---- shared brand strip ----------------------------------------------- */
  function brandbar(opts) {
    opts = opts || {};
    return U.el("div.brandstrip", null, [
      U.el("div.brand-mark", null, [
        U.el("span.brand-dot"),
        U.el("span.brand-name", { text: "DISASM" }),
        U.el("span.brand-name-2", { text: "STUDIO" })
      ]),
      opts.center || U.el("span.grow"),
      U.el("button.brand-cmd", { title: "Command palette  (Ctrl+K)", onclick: open }, [
        U.el("span.mono", { text: "Ctrl" }), U.el("span.brand-cmd-k", { text: "K" })
      ])
    ]);
  }

  /* seed the palette with a couple of always-present commands */
  command({ id: "app.palette", title: "Command Palette", group: "App", keys: ["ctrl+k"], run: open });

  window.APP = {
    ready: ready,
    command: command,
    removeCommand: removeCommand,
    palette: { open: open, close: close, toggle: toggle },
    keymap: { register: command },
    brandbar: brandbar,
    prettyKeys: prettyKeys
  };
})();
