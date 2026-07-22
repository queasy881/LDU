/* ============================================================================
   util.js — DOM helpers, formatting, and the token colorizers.
   Fresh for the AXIOM rebuild. Everything hangs off window.U.
   Address formatting is BigInt-safe: RVAs live above 2^53 for x64 images.
   ============================================================================ */
(function () {
  "use strict";

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  /* el("div.cls#id", {attr}, children) — tiny hyperscript.
     attrs special keys: text, html, style(obj|str), dataset(obj), on*(fn),
     class (added to whatever the spec set). Boolean true => bare attribute. */
  function el(spec, attrs, kids) {
    var tag = (/^([a-z0-9]+)/i.exec(spec) || [0, "div"])[1];
    var node = document.createElement(tag);
    var rest = spec.slice(tag.length), re = /([.#])([\w-]+)/g, x;
    while ((x = re.exec(rest))) { if (x[1] === ".") node.classList.add(x[2]); else node.id = x[2]; }
    if (attrs) for (var k in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
      var v = attrs[k]; if (v == null) continue;
      if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v;
      else if (k === "class") node.className += (node.className ? " " : "") + v;
      else if (k === "style") { if (typeof v === "string") node.style.cssText = v; else for (var s in v) node.style[s] = v[s]; }
      else if (k === "dataset") { for (var d in v) node.dataset[d] = v[d]; }
      else if (k.slice(0, 2) === "on" && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) node.setAttribute(k, "");
      else if (v !== false) node.setAttribute(k, v);
    }
    if (kids != null) append(node, kids);
    return node;
  }
  function append(node, kids) {
    if (Array.isArray(kids)) { for (var i = 0; i < kids.length; i++) append(node, kids[i]); }
    else if (kids != null) { if (kids.nodeType) node.appendChild(kids); else node.appendChild(document.createTextNode(String(kids))); }
  }
  function clear(node) { if (node) while (node.firstChild) node.removeChild(node.firstChild); return node; }

  function toBig(n) {
    if (typeof n === "bigint") return n < 0n ? -n : n;
    if (typeof n === "string") { var t = n.trim(); try { return /^0x/i.test(t) || /^[0-9]+$/.test(t) ? BigInt(t) : BigInt(Math.trunc(Number(t)) || 0); } catch (e) { return 0n; } }
    if (typeof n === "number") { if (!isFinite(n)) return 0n; try { return BigInt(Math.trunc(n)); } catch (e) { return 0n; } }
    return 0n;
  }
  function hex(n) { return "0x" + toBig(n).toString(16); }
  function addr(n, w) { var s = toBig(n).toString(16); w = w || 6; while (s.length < w) s = "0" + s; return "0x" + s; }
  function bytesFmt(input) {
    if (input == null) return "";
    if (typeof input === "string") return input.trim().toLowerCase();
    var out = []; for (var i = 0; i < input.length; i++) { var v = input[i] & 0xff; out.push((v < 16 ? "0" : "") + v.toString(16)); }
    return out.join(" ");
  }

  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

  function debounce(fn, ms) {
    var t = null;
    function w() { var c = this, a = arguments; if (t) clearTimeout(t); t = setTimeout(function () { t = null; fn.apply(c, a); }, ms); }
    w.cancel = function () { if (t) { clearTimeout(t); t = null; } };
    return w;
  }
  function raf(fn) { return window.requestAnimationFrame(fn); }

  /* ---- x86 register classification for operand coloring -------------------- */
  var REGSET = {};
  ("rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 " +
   "eax ebx ecx edx esi edi ebp esp r8d r9d r10d r11d r12d r13d r14d r15d " +
   "ax bx cx dx si di bp sp al bl cl dl ah bh ch dh sil dil bpl spl " +
   "r8b r9b r10b r11b r12b r13b r14b r15b r8w r9w r10w r11w r12w r13w r14w r15w").split(" ")
    .forEach(function (r) { REGSET[r] = true; });
  var SIMD = /^(xmm|ymm|zmm)\d+$/;
  var SEG = /^(cs|ds|es|fs|gs|ss)$/;

  function regKind(tok) {
    var t = tok.toLowerCase();
    if (t === "rip" || t === "eip") return "rip";
    if (SIMD.test(t)) return "simd";
    if (SEG.test(t)) return "seg";
    if (REGSET[t]) return "reg";
    return null;
  }

  /* Colorize an operand string into HTML spans. Lexical, plus a hint from
     ref_type (1=call 2=jmp 4=jcc) so branch/call targets get the accent. */
  function colorOperands(ops, refType) {
    if (!ops) return "";
    var out = "", re = /(0x[0-9a-fA-F]+)|(\b\d+\b)|([a-zA-Z_$.][\w$.]*)|(\s+)|([\[\],+\-*:!])|(.)/g, m;
    var isTarget = refType === 1 || refType === 2 || refType === 4;
    while ((m = re.exec(ops))) {
      if (m[1]) out += '<span class="' + (isTarget ? "t-target" : "t-imm") + '">' + esc(m[1]) + "</span>";
      else if (m[2]) out += '<span class="t-imm">' + esc(m[2]) + "</span>";
      else if (m[3]) {
        var rk = regKind(m[3]);
        if (rk) out += '<span class="t-' + (rk === "simd" ? "simd" : rk === "rip" ? "rip" : rk === "seg" ? "seg" : "reg") +
          '" data-reg="' + esc(m[3].toLowerCase()) + '">' + esc(m[3]) + "</span>";
        else if (/^(byte|word|dword|qword|xmmword|ymmword|ptr|offset|near|far|short)$/i.test(m[3])) out += '<span class="t-size">' + esc(m[3]) + "</span>";
        else out += '<span class="t-sym">' + esc(m[3]) + "</span>";
      }
      else if (m[4]) out += m[4];
      else if (m[5]) out += '<span class="t-punc">' + esc(m[5]) + "</span>";
      else out += esc(m[6]);
    }
    return out;
  }

  /* small C tokenizer for the decompile panel */
  var C_KW = {};
  ("void char short int long float double signed unsigned struct union enum const volatile " +
   "static return if else for while do switch case break continue goto default sizeof typedef " +
   "int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t size_t intptr_t uintptr_t " +
   "bool true false NULL __int64 __int32 __int16 __int8 __fastcall __stdcall __cdecl __thiscall __declspec")
    .split(" ").forEach(function (k) { C_KW[k] = true; });

  /* Decode runs of C octal escapes (\NNN) as UTF-8 so byte-escaped multibyte
     text — e.g. \342\225\224...\342\225\227 — renders as its real characters
     (╔══...╗). Consecutive octal escapes are gathered so multi-byte code points
     combine; named escapes (\n \t \\ \") and plain text pass through untouched. */
  function decodeOctalUtf8(s) {
    var out = "", i = 0, n = s.length, buf = [];
    function flush() {
      if (!buf.length) return;
      try {
        if (typeof TextDecoder !== "undefined") out += new TextDecoder("utf-8").decode(new Uint8Array(buf));
        else out += decodeURIComponent(buf.map(function (b) { return "%" + (b < 16 ? "0" : "") + b.toString(16); }).join(""));
      } catch (e) { out += buf.map(function (b) { return "\\" + ("00" + b.toString(8)).slice(-3); }).join(""); }
      buf = [];
    }
    while (i < n) {
      if (s[i] === "\\" && i + 1 < n && s[i + 1] >= "0" && s[i + 1] <= "7") {
        var j = i + 1, oct = "";
        while (j < n && oct.length < 3 && s[j] >= "0" && s[j] <= "7") { oct += s[j]; j++; }
        buf.push(parseInt(oct, 8) & 0xff); i = j; continue;
      }
      flush(); out += s[i]; i++;
    }
    flush();
    return out;
  }

  function colorC(src) {
    var out = "", i = 0, n = src.length;
    function push(cls, s) { out += '<span class="' + cls + '">' + esc(s) + "</span>"; }
    while (i < n) {
      var c = src[i];
      if (c === "/" && src[i + 1] === "*") { var j = src.indexOf("*/", i + 2); j = j < 0 ? n : j + 2; push("c-cmt", src.slice(i, j)); i = j; continue; }
      if (c === "/" && src[i + 1] === "/") { var k = src.indexOf("\n", i); k = k < 0 ? n : k; push("c-cmt", src.slice(i, k)); i = k; continue; }
      if (c === '"' || c === "'") { var q = c, e = i + 1; while (e < n && src[e] !== q) { if (src[e] === "\\") e++; e++; } e = Math.min(e + 1, n); push("c-str", decodeOctalUtf8(src.slice(i, e))); i = e; continue; }
      if (c === "#") { var p = src.indexOf("\n", i); p = p < 0 ? n : p; push("c-pre", src.slice(i, p)); i = p; continue; }
      if (/[0-9]/.test(c)) { var d = i; while (d < n && /[0-9a-fA-FxX._]/.test(src[d])) d++; push("c-num", src.slice(i, d)); i = d; continue; }
      if (/[A-Za-z_]/.test(c)) {
        var w = i; while (w < n && /[A-Za-z0-9_]/.test(src[w])) w++;
        var word = src.slice(i, w), after = src.slice(w).match(/^\s*\(/);
        if (C_KW[word]) push("c-kw", word);
        else if (after) push("c-fn", word);
        else out += esc(word);
        i = w; continue;
      }
      out += esc(c); i++;
    }
    return out;
  }

  function copy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) {} document.body.removeChild(ta); return Promise.resolve();
  }

  function toast(msg, kind) {
    var host = $("#toasts") || (function () { var h = el("div#toasts"); document.body.appendChild(h); return h; })();
    var t = el("div.toast" + (kind ? "." + kind : ""), { text: msg });
    host.appendChild(t); raf(function () { t.classList.add("in"); });
    setTimeout(function () { t.classList.remove("in"); setTimeout(function () { t.remove(); }, 200); }, 2200);
  }

  window.U = {
    $: $, $all: $all, el: el, append: append, clear: clear, esc: esc,
    hex: hex, addr: addr, bytesFmt: bytesFmt, toBig: toBig,
    debounce: debounce, raf: raf,
    colorOperands: colorOperands, colorC: colorC, regKind: regKind,
    copy: copy, toast: toast
  };
})();
