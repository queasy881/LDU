/* ============================================================================
   util.js — tiny DOM + formatting helpers. No framework. Exposed on window.
   ========================================================================== */
(function () {
  "use strict";

  /* el(tag, props?, children?) — create an element.
     props: attributes; special keys: class/className, style(obj|string),
            text/textContent, html/innerHTML, dataset(obj), and on* handlers.
     children: node | string | array of (node|string), nullish skipped. */
  function el(tag, props, children) {
    var node = document.createElement(tag);
    if (props) {
      for (var k in props) {
        if (!Object.prototype.hasOwnProperty.call(props, k)) continue;
        var v = props[k];
        if (v == null) continue;
        if (k === "class" || k === "className") {
          node.className = v;
        } else if (k === "text" || k === "textContent") {
          node.textContent = v;
        } else if (k === "html" || k === "innerHTML") {
          node.innerHTML = v;
        } else if (k === "style") {
          if (typeof v === "string") node.style.cssText = v;
          else for (var s in v) if (Object.prototype.hasOwnProperty.call(v, s)) node.style[s] = v[s];
        } else if (k === "dataset") {
          for (var d in v) if (Object.prototype.hasOwnProperty.call(v, d)) node.dataset[d] = v[d];
        } else if (k.length > 2 && k.slice(0, 2) === "on" && typeof v === "function") {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else {
          node.setAttribute(k, v);
        }
      }
    }
    if (children != null) append(node, children);
    return node;
  }

  function append(node, children) {
    if (Array.isArray(children)) {
      for (var i = 0; i < children.length; i++) append(node, children[i]);
    } else if (children != null) {
      if (children.nodeType) node.appendChild(children);
      else node.appendChild(document.createTextNode(String(children)));
    }
  }

  /* coerce to a non-negative BigInt-safe-ish unsigned value, tolerating
     Number, string, or BigInt input. Returns a Number when it fits, else uses
     string formatting via BigInt to avoid precision loss on >2^53 addrs. */
  function toHexBig(n) {
    if (typeof n === "bigint") return n < 0n ? -n : n;
    if (typeof n === "string") {
      var t = n.trim();
      try {
        if (/^0x/i.test(t)) return BigInt(t);
        if (/^[0-9]+$/.test(t)) return BigInt(t);
        return BigInt(Math.trunc(Number(t)) || 0);
      } catch (e) { return 0n; }
    }
    if (typeof n === "number") {
      if (!isFinite(n)) return 0n;
      try { return BigInt(Math.trunc(n)); } catch (e) { return 0n; }
    }
    return 0n;
  }

  /* hex(n) -> "0x..." lowercase, no padding */
  function hex(n) {
    var b = toHexBig(n);
    return "0x" + b.toString(16);
  }

  /* fmtAddr(n, width=8) -> "0x" + zero-padded lowercase hex */
  function fmtAddr(n, width) {
    if (width == null) width = 8;
    var s = toHexBig(n).toString(16);
    while (s.length < width) s = "0" + s;
    return "0x" + s;
  }

  /* fmtBytes(input) -> "48 89 e5" lowercase space-separated.
     Accepts: array/typed-array of byte numbers, or a pre-joined string. */
  function fmtBytes(input) {
    if (input == null) return "";
    if (typeof input === "string") return input.trim().toLowerCase();
    var out = [];
    for (var i = 0; i < input.length; i++) {
      var v = input[i] & 0xff;
      out.push((v < 16 ? "0" : "") + v.toString(16));
    }
    return out.join(" ");
  }

  /* debounce(fn, ms) -> debounced fn with .cancel() */
  function debounce(fn, ms) {
    var t = null;
    function wrapped() {
      var ctx = this, args = arguments;
      if (t) clearTimeout(t);
      t = setTimeout(function () { t = null; fn.apply(ctx, args); }, ms);
    }
    wrapped.cancel = function () { if (t) { clearTimeout(t); t = null; } };
    return wrapped;
  }

  /* clear(node) -> remove all children (fast) */
  function clear(node) {
    if (!node) return node;
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  /* classToggle(node, name, on?) -> add/remove (or toggle if on omitted) */
  function classToggle(node, name, on) {
    if (!node) return;
    if (on === undefined) node.classList.toggle(name);
    else if (on) node.classList.add(name);
    else node.classList.remove(name);
  }

  /* escapeHtml — used when building innerHTML strings safely. */
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  window.DSUtil = {
    el: el,
    hex: hex,
    fmtAddr: fmtAddr,
    fmtBytes: fmtBytes,
    debounce: debounce,
    clear: clear,
    classToggle: classToggle,
    escapeHtml: escapeHtml,
    toHexBig: toHexBig
  };
  /* also expose the most-used helpers at top level for terse screen code */
  window.el = el;
  window.hex = hex;
  window.fmtAddr = fmtAddr;
  window.fmtBytes = fmtBytes;
  window.debounce = debounce;
  window.clear = clear;
  window.classToggle = classToggle;
})();
