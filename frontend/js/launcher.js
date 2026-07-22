/* ============================================================================
   launcher.js — minimal launcher controller.
     new  -> inline name form -> new_project
     open -> native open_project_dialog
     recent list -> open_project_path
   ============================================================================ */
(function () {
  "use strict";
  var U = window.U, DS = window.DS, APP = window.APP;

  APP.ready(function () {
    U.$("#lc-new").addEventListener("click", showNewForm);
    U.$("#lc-cancel").addEventListener("click", hideNewForm);
    U.$("#lc-newform").addEventListener("submit", function (e) { e.preventDefault(); createProject(); });
    U.$("#lc-open").addEventListener("click", openDialog);
    U.$("#lc-refresh").addEventListener("click", loadRecent);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !U.$("#lc-newform").hidden) hideNewForm(); });

    loadRecent();
    window.addEventListener("focus", loadRecent);

    APP.command({ id: "lc.new", title: "New Project", group: "Launch", keys: ["ctrl+n"], run: showNewForm });
    APP.command({ id: "lc.open", title: "Open Project…", group: "Launch", keys: ["ctrl+o"], run: openDialog });
    APP.command({ id: "lc.reload", title: "Reload Recent", group: "Launch", keys: ["ctrl+r"], run: loadRecent });
  });

  function showNewForm() {
    U.$("#lc-error").hidden = true;
    U.$("#lc-newform").hidden = false;
    var n = U.$("#lc-name"); n.value = ""; n.focus();
  }
  function hideNewForm() { U.$("#lc-newform").hidden = true; U.$("#lc-error").hidden = true; }

  function createProject() {
    var name = U.$("#lc-name").value.trim();
    if (!name) { showErr("Project name required."); U.$("#lc-name").focus(); return; }
    DS.invoke("new_project", { name: name }).then(function () {
      hideNewForm();
      setTimeout(loadRecent, 400);
    }).catch(showErr);
  }

  function openDialog() { DS.invoke("open_project_dialog").catch(showErr); }

  function loadRecent() {
    DS.invoke("list_recent_projects").then(function (list) {
      list = list || [];
      var host = U.clear(U.$("#lc-list"));
      U.$("#lc-empty").hidden = list.length > 0;
      var cnt = U.$("#side-count"); if (cnt) cnt.textContent = list.length ? String(list.length) : "";
      list.forEach(function (p) {
        var n = p.binary_count || 0;
        host.appendChild(U.el("button.rp", { type: "button", title: p.path,
          onclick: function () { DS.invoke("open_project_path", { path: p.path }).catch(showErr); } }, [
          U.el("span.rp-name", { text: p.name }),
          U.el("span.rp-path", { text: p.path }),
          U.el("span.rp-count", { text: n + (n === 1 ? " binary" : " binaries") })
        ]));
      });
    }).catch(function () {});
  }

  function showErr(e) {
    var box = U.$("#lc-error");
    box.textContent = (e && e.message) ? e.message : String(e || "error");
    box.hidden = false;
  }
})();
