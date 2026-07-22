/* ============================================================================
   vlist.js — windowed virtual list, fixed recycled-pool design.
   Rather than mounting/unmounting a changing set of nodes, we allocate ONE pool
   of (viewport + overscan) row slots and reassign each slot's index + transform
   as the user scrolls. DOM node count is constant regardless of total rows, so a
   million-row listing scrolls at 60fps.

   window.VL.create(container, {
     rowHeight,           // fixed px height per row
     total,               // row count
     render(index, slot)  // fill `slot` (an empty div) for row `index`
     overscan?            // extra rows kept above+below viewport (default 6)
   }) -> { setTotal, refresh, scrollTo, topIndex, el, destroy }
   ============================================================================ */
(function () {
  "use strict";

  function create(container, opts) {
    opts = opts || {};
    var rowH = Math.max(1, opts.rowHeight | 0) || 20;
    var total = Math.max(0, opts.total | 0);
    var overscan = opts.overscan == null ? 6 : Math.max(0, opts.overscan | 0);
    var render = opts.render || function () {};
    if (!container) throw new Error("VL: container required");

    var cs = getComputedStyle(container);
    if (cs.position === "static") container.style.position = "relative";
    container.style.overflow = "auto";

    var spacer = document.createElement("div");
    spacer.className = "vl-spacer";
    spacer.style.cssText = "position:absolute;top:0;left:0;width:1px;pointer-events:none;opacity:0";
    var layer = document.createElement("div");
    layer.className = "vl-layer";
    layer.style.cssText = "position:absolute;top:0;left:0;right:0;will-change:transform";
    container.appendChild(spacer);
    container.appendChild(layer);

    var pool = [];          // { el, index }
    var poolSize = 0;
    var pending = 0;
    var dead = false;

    function setHeight() { spacer.style.height = (total * rowH) + "px"; }
    setHeight();

    function ensurePool() {
      var h = container.clientHeight || 600;
      var need = Math.ceil(h / rowH) + overscan * 2 + 2;
      while (poolSize < need) {
        var d = document.createElement("div");
        d.className = "vl-row";
        d.style.cssText = "position:absolute;left:0;right:0;height:" + rowH + "px";
        layer.appendChild(d);
        pool.push({ el: d, index: -1 });
        poolSize++;
      }
      // hide any surplus slots (viewport shrank)
      for (var i = need; i < poolSize; i++) pool[i].el.style.display = "none";
      for (var j = 0; j < Math.min(need, poolSize); j++) pool[j].el.style.display = "";
      return need;
    }

    function paint() {
      pending = 0;
      if (dead) return;
      var need = ensurePool();
      var top = container.scrollTop;
      var start = Math.floor(top / rowH) - overscan;
      if (start < 0) start = 0;
      if (start > Math.max(0, total - 1)) start = Math.max(0, total - 1);
      for (var s = 0; s < poolSize; s++) {
        var slot = pool[s];
        if (s >= need) { slot.index = -1; continue; }
        var idx = start + s;
        if (idx >= total) { slot.el.style.display = "none"; slot.index = -1; continue; }
        slot.el.style.display = "";
        slot.el.style.transform = "translateY(" + (idx * rowH) + "px)";
        if (slot.index !== idx || slot.dirty) {
          slot.index = idx; slot.dirty = false;
          while (slot.el.firstChild) slot.el.removeChild(slot.el.firstChild);
          slot.el.dataset.index = idx;
          render(idx, slot.el);
        }
      }
    }

    function schedule() { if (!pending && !dead) pending = requestAnimationFrame(paint); }

    container.addEventListener("scroll", schedule, { passive: true });
    var ro = null;
    if (typeof ResizeObserver !== "undefined") { ro = new ResizeObserver(schedule); ro.observe(container); }
    else window.addEventListener("resize", schedule);

    /* mark all mounted slots dirty so their content is rebuilt on next paint */
    function refresh() { for (var i = 0; i < poolSize; i++) pool[i].dirty = true; paint(); }

    function setTotal(n) {
      total = Math.max(0, n | 0);
      setHeight();
      var maxTop = Math.max(0, total * rowH - (container.clientHeight || 0));
      if (container.scrollTop > maxTop) container.scrollTop = maxTop;
      for (var i = 0; i < poolSize; i++) pool[i].index = -1; // force re-render
      paint();
    }

    function scrollTo(index, align) {
      if (dead || total === 0) return;
      index = Math.min(Math.max(0, index | 0), total - 1);
      var h = container.clientHeight || 0, target;
      if (align === "center") target = index * rowH - (h / 2 - rowH / 2);
      else target = (index - 3) * rowH;
      target = Math.max(0, Math.min(target, Math.max(0, total * rowH - h)));
      container.scrollTop = target;
      paint();
    }

    function topIndex() { return Math.floor(container.scrollTop / rowH); }

    function destroy() {
      dead = true;
      if (pending) cancelAnimationFrame(pending);
      container.removeEventListener("scroll", schedule);
      if (ro) ro.disconnect(); else window.removeEventListener("resize", schedule);
      try { container.removeChild(layer); container.removeChild(spacer); } catch (e) {}
    }

    paint();
    return {
      el: container, setTotal: setTotal, refresh: refresh, scrollTo: scrollTo,
      topIndex: topIndex, destroy: destroy,
      get total() { return total; }, get rowHeight() { return rowH; }
    };
  }

  window.VL = { create: create };
})();
