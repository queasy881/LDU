/* ============================================================================
   project.js — project window controller. Lists the project's binaries, adds
   new ones (exe/dll/sys) via native dialog, opens one into a disasm window, and
   removes them. All annotations live in the .dsproj the backend persists.
   ========================================================================== */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  (function ready() {
    if (!window.DS || !window.DSUtil) return void setTimeout(ready, 20);
    init();
  })();

  function init() {
    $("pj-add").addEventListener("click", function () {
      $("pj-add").disabled = true;
      DS.invoke("add_binary").then(function (r) {
        render(r && r.binaries);
      }).catch(showErr).then(function () { $("pj-add").disabled = false; });
    });
    refresh();
    window.addEventListener("focus", refresh);
  }

  function refresh() {
    DS.invoke("get_project").then(function (p) {
      if (p && p.name) { document.title = "DisasmStudio — " + p.name; $("pj-name").textContent = p.name; }
      render(p && p.binaries);
    }).catch(showErr);
  }

  function extOf(name) {
    var m = /\.([a-z0-9]+)$/i.exec(name || "");
    return m ? m[1].toUpperCase().slice(0, 4) : "BIN";
  }

  function render(binaries) {
    binaries = binaries || [];
    $("bin-count").textContent = binaries.length ? (binaries.length + (binaries.length === 1 ? " binary" : " binaries")) : "";
    $("bin-empty").hidden = binaries.length > 0;
    var host = DSUtil.clear($("bin-list"));

    binaries.forEach(function (b) {
      var badges = [];
      if (b.format) badges.push(el("span", { class: "badge", text: b.format }));
      if (b.arch) badges.push(el("span", { class: "badge", text: b.arch }));

      host.appendChild(el("div", { class: "bin-row" }, [
        el("div", { class: "bin-icon mono", text: extOf(b.name) }),
        el("div", { class: "bin-main" }, [
          el("div", { class: "bin-name", text: b.name }),
          el("div", { class: "bin-path", text: b.path, title: b.path })
        ]),
        el("div", { class: "bin-badges" }, badges),
        el("div", { class: "bin-actions" }, [
          el("button", {
            class: "btn btn-sm btn-primary",
            onclick: function () { openBinary(b.id, this); }
          }, "Open"),
          el("button", {
            class: "btn btn-sm btn-ghost btn-danger",
            onclick: function () { removeBinary(b.id); }
          }, "Remove")
        ])
      ]));
    });
  }

  function openBinary(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "Opening…"; }
    DS.invoke("open_binary", { id: id }).then(function () {
      if (btn) setTimeout(function () { btn.disabled = false; btn.textContent = "Open"; }, 800);
    }).catch(function (e) {
      showErr(e); if (btn) { btn.disabled = false; btn.textContent = "Open"; }
    });
  }

  function removeBinary(id) {
    DS.invoke("remove_binary", { id: id }).then(function (r) {
      render(r && r.binaries);
    }).catch(showErr);
  }

  function showErr(e) {
    var box = $("pj-error");
    box.textContent = (e && e.message) ? e.message : String(e || "error");
    box.hidden = false;
    setTimeout(function () { box.hidden = true; }, 5000);
  }
})();
