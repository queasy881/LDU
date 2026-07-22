/* ============================================================================
   project.js — BLUEPRINT project controller.
   Renders each binary as a component "spec sheet", adds via native dialog,
   opens one into a disasm window, removes it.
   Uses window.DS (transport), window.U (dom), window.APP (palette/keymap).
   ============================================================================ */
(function () {
  "use strict";
  var U = window.U, DS = window.DS, APP = window.APP;

  APP.ready(function () {
    U.$("#pj-add").addEventListener("click", addBinary);
    refresh();
    window.addEventListener("focus", refresh);
    APP.command({ id: "pj.add", title: "Analyze New Binary…", group: "Project", keys: ["ctrl+o"], run: addBinary });
    APP.command({ id: "pj.refresh", title: "Refresh Project", group: "Project", keys: ["ctrl+r"], run: refresh });
  });

  function addBinary() {
    var btn = U.$("#pj-add"); btn.disabled = true;
    DS.invoke("add_binary")
      .then(function (r) { render(r && r.binaries); })
      .catch(showErr)
      .then(function () { btn.disabled = false; });
  }

  function refresh() {
    DS.invoke("get_project").then(function (p) {
      if (p && p.name) { document.title = "DisasmStudio — " + p.name; U.$("#pj-name").textContent = p.name; }
      render(p && p.binaries);
    }).catch(showErr);
  }

  function extOf(name) { var m = /\.([a-z0-9]+)$/i.exec(name || ""); return m ? m[1].toUpperCase().slice(0, 4) : "BIN"; }

  function render(binaries) {
    binaries = binaries || [];
    U.$("#bin-count").textContent = binaries.length ? String(binaries.length).padStart(2, "0") + " item" + (binaries.length === 1 ? "" : "s") : "";
    U.$("#bin-empty").hidden = binaries.length > 0;
    var host = U.clear(U.$("#bin-list"));

    binaries.forEach(function (b) {
      host.appendChild(U.el("article.spec", null, [
        U.el("header.spec-head", null, [
          U.el("span.spec-ext", { text: extOf(b.name) }),
          U.el("span.spec-name", { text: b.name, title: b.name })
        ]),
        U.el("div.spec-rows", null, [
          specRow("FORMAT", b.format || "—", true),
          specRow("ARCH", b.arch || "—", true),
          specRow("PATH", b.path || "—", false, b.path)
        ]),
        U.el("footer.spec-actions", null, [
          U.el("button.sp-btn.sp-open", { text: "Open ▸", onclick: function () { openBinary(b.id, this); } }),
          U.el("button.sp-btn.sp-rm", { text: "remove", onclick: function () { removeBinary(b.id); } })
        ])
      ]));
    });
  }

  function specRow(k, v, hi, title) {
    return U.el("div.spec-row", null, [
      U.el("span.spec-k", { text: k }),
      U.el("span.spec-v" + (hi ? ".hi" : ""), { text: v, title: title || v })
    ]);
  }

  function openBinary(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "Opening…"; }
    DS.invoke("open_binary", { id: id }).then(function () {
      if (btn) setTimeout(function () { btn.disabled = false; btn.textContent = "Open ▸"; }, 800);
    }).catch(function (e) { showErr(e); if (btn) { btn.disabled = false; btn.textContent = "Open ▸"; } });
  }

  function removeBinary(id) {
    DS.invoke("remove_binary", { id: id }).then(function (r) { render(r && r.binaries); }).catch(showErr);
  }

  function showErr(e) {
    var box = U.$("#pj-error");
    box.textContent = "⚠ " + ((e && e.message) ? e.message : String(e || "error"));
    box.hidden = false;
    setTimeout(function () { box.hidden = true; }, 5000);
  }
})();
