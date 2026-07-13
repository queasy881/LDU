/* ============================================================================
   launcher.js — welcome window controller. New Project (inline name), Open
   Project (native dialog), and a clickable recent-projects list.
   ========================================================================== */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  (function ready() {
    if (!window.DS || !window.DSUtil) return void setTimeout(ready, 20);
    init();
  })();

  function init() {
    $("lc-new").addEventListener("click", showNewForm);
    $("lc-cancel").addEventListener("click", hideNewForm);
    $("lc-newform").addEventListener("submit", function (e) { e.preventDefault(); createProject(); });
    $("lc-open").addEventListener("click", function () {
      DS.invoke("open_project_dialog").catch(showErr);
    });
    $("lc-refresh").addEventListener("click", loadRecent);
    window.addEventListener("focus", loadRecent);
    loadRecent();
  }

  function showNewForm() {
    $("lc-error").hidden = true;
    $("lc-newform").hidden = false;
    var n = $("lc-name"); n.value = ""; n.focus();
  }
  function hideNewForm() { $("lc-newform").hidden = true; $("lc-error").hidden = true; }

  function createProject() {
    var name = $("lc-name").value.trim();
    if (!name) { showErr("Please enter a project name."); $("lc-name").focus(); return; }
    DS.invoke("new_project", { name: name }).then(function () {
      hideNewForm();
      // The project window opens natively; refresh the recent list shortly after.
      setTimeout(loadRecent, 400);
    }).catch(showErr);
  }

  function loadRecent() {
    DS.invoke("list_recent_projects").then(function (list) {
      list = list || [];
      var host = DSUtil.clear($("lc-list"));
      $("lc-empty").hidden = list.length > 0;
      list.forEach(function (p) {
        host.appendChild(el("div", {
          class: "lc-item",
          title: p.path,
          onclick: function () { DS.invoke("open_project_path", { path: p.path }).catch(showErr); }
        }, [
          el("div", { class: "lc-main" }, [
            el("div", { class: "lc-name", text: p.name }),
            el("div", { class: "lc-path", text: p.path })
          ]),
          el("span", { class: "badge lc-count", text: p.binary_count + (p.binary_count === 1 ? " binary" : " binaries") }),
          el("span", { class: "lc-go", text: "→" })
        ]));
      });
    }).catch(function () { /* host not ready / no projects */ });
  }

  function showErr(e) {
    var box = $("lc-error");
    box.textContent = (e && e.message) ? e.message : String(e || "error");
    box.hidden = false;
  }
})();
