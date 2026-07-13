/* ============================================================================
   vlist.js — windowed virtual list. Absolutely-positioned recycled rows over a
   tall spacer. Stays 60fps at 1,000,000+ rows because only visible+overscan
   rows ever exist in the DOM.

   API (frozen contract section F):
     new VList(container, {
       rowHeight: Number,
       total: Number,
       render(index) -> HTMLElement,   // MUST be synchronous; may be a placeholder
       overscan?: Number               // extra rows above+below the viewport
     })
     -> { setTotal(n), refresh(), scrollToIndex(i), el }

   The container is the scroll viewport. We create:
     - a spacer (height = total * rowHeight) to drive the native scrollbar
     - rows positioned with transform: translateY(index * rowHeight)
   render(index) returns a row element; we reuse the returned node identity per
   slot when possible, but always call render(index) so callers can repaint with
   freshly-arrived async data (then call refresh()).
   ========================================================================== */
(function () {
  "use strict";

  function VList(container, opts) {
    opts = opts || {};
    var rowHeight = Math.max(1, opts.rowHeight | 0) || 20;
    var total = Math.max(0, opts.total | 0);
    var overscan = opts.overscan == null ? 8 : Math.max(0, opts.overscan | 0);
    var renderFn = typeof opts.render === "function" ? opts.render : function () {
      var d = document.createElement("div"); return d;
    };

    if (!container) throw new Error("VList: container required");

    // viewport setup
    if (getComputedStyle(container).position === "static") {
      container.style.position = "relative";
    }
    container.style.overflowY = "auto";
    container.style.overflowX = "hidden";

    // spacer drives scroll height
    var spacer = document.createElement("div");
    spacer.style.position = "absolute";
    spacer.style.top = "0";
    spacer.style.left = "0";
    spacer.style.width = "1px";
    spacer.style.pointerEvents = "none";
    spacer.style.visibility = "hidden";

    // rows live in a layer that we translate; rows themselves are translated
    var layer = document.createElement("div");
    layer.style.position = "absolute";
    layer.style.top = "0";
    layer.style.left = "0";
    layer.style.right = "0";
    layer.style.willChange = "transform";

    container.appendChild(spacer);
    container.appendChild(layer);

    // current mounted slot map: index -> { node }
    var mounted = Object.create(null);
    var firstIndex = -1, lastIndex = -2; // inclusive window currently mounted
    var raf = 0;
    var destroyed = false;

    function setSpacer() {
      spacer.style.height = (total * rowHeight) + "px";
    }
    setSpacer();

    function visibleRange() {
      var scrollTop = container.scrollTop;
      var h = container.clientHeight || 0;
      var start = Math.floor(scrollTop / rowHeight) - overscan;
      var visCount = Math.ceil(h / rowHeight) + overscan * 2 + 1;
      if (start < 0) start = 0;
      var end = start + visCount - 1;
      if (end > total - 1) end = total - 1;
      if (total === 0) { start = 0; end = -1; }
      return { start: start, end: end };
    }

    function placeNode(node, index) {
      node.style.position = "absolute";
      node.style.top = "0";
      node.style.left = "0";
      node.style.right = "0";
      node.style.transform = "translateY(" + (index * rowHeight) + "px)";
      node.style.height = rowHeight + "px";
    }

    // Mount/unmount only the delta between old window and new window.
    function sync() {
      raf = 0;
      if (destroyed) return;
      var r = visibleRange();
      var start = r.start, end = r.end;

      // If windows don't overlap at all, drop everything and rebuild.
      if (start > lastIndex || end < firstIndex || firstIndex > lastIndex) {
        for (var k in mounted) {
          var i = +k;
          if (i < start || i > end) {
            layer.removeChild(mounted[k].node);
            delete mounted[k];
          }
        }
      } else {
        // remove rows that scrolled out
        for (var k2 in mounted) {
          var i2 = +k2;
          if (i2 < start || i2 > end) {
            layer.removeChild(mounted[k2].node);
            delete mounted[k2];
          }
        }
      }

      // add rows that scrolled in
      for (var idx = start; idx <= end; idx++) {
        if (mounted[idx]) continue;
        var node = renderFn(idx);
        if (!node) {
          node = document.createElement("div");
        }
        placeNode(node, idx);
        layer.appendChild(node);
        mounted[idx] = { node: node };
      }

      firstIndex = start;
      lastIndex = end;
    }

    function schedule() {
      if (raf || destroyed) return;
      raf = requestAnimationFrame(sync);
    }

    function onScroll() { schedule(); }
    container.addEventListener("scroll", onScroll, { passive: true });

    // ResizeObserver keeps the window correct when the viewport changes size.
    var ro = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(function () { schedule(); });
      ro.observe(container);
    } else {
      window.addEventListener("resize", schedule);
    }

    // ---- public API ----

    // refresh(): re-run render(index) for the currently-mounted window in place.
    // Used when async data arrives so rows can repaint without changing scroll.
    function refresh() {
      if (destroyed) return;
      var keep = mounted;
      mounted = Object.create(null);
      for (var k in keep) {
        var idx = +k;
        var old = keep[k].node;
        if (idx < 0 || idx > total - 1) { layer.removeChild(old); continue; }
        var fresh = renderFn(idx);
        if (!fresh) fresh = document.createElement("div");
        placeNode(fresh, idx);
        if (fresh === old) {
          // same node identity reused by caller — keep it
          mounted[idx] = { node: fresh };
        } else {
          layer.replaceChild(fresh, old);
          mounted[idx] = { node: fresh };
        }
      }
      // ensure any newly-visible slots get filled too
      schedule();
    }

    function setTotal(n) {
      n = Math.max(0, n | 0);
      total = n;
      setSpacer();
      // clamp scroll if we shrank below current position
      var maxScroll = Math.max(0, total * rowHeight - (container.clientHeight || 0));
      if (container.scrollTop > maxScroll) container.scrollTop = maxScroll;
      // drop now-out-of-range rows
      for (var k in mounted) {
        var i = +k;
        if (i > total - 1) {
          layer.removeChild(mounted[k].node);
          delete mounted[k];
        }
      }
      firstIndex = -1; lastIndex = -2;
      // force a full resync next frame
      sync();
    }

    // scrollToIndex(i): bring row i into view, anchored near the top with a
    // small margin, clamped to bounds.
    function scrollToIndex(i, align) {
      if (destroyed) return;
      i = i | 0;
      if (i < 0) i = 0;
      if (i > total - 1) i = total - 1;
      if (total === 0) return;
      var target;
      var h = container.clientHeight || 0;
      if (align === "center") {
        target = i * rowHeight - (h / 2 - rowHeight / 2);
      } else {
        // top-ish with a 3-row margin so context above is visible
        target = (i - 3) * rowHeight;
      }
      if (target < 0) target = 0;
      var maxScroll = Math.max(0, total * rowHeight - h);
      if (target > maxScroll) target = maxScroll;
      container.scrollTop = target;
      sync(); // immediate so a follow-up read sees the row
    }

    function destroy() {
      destroyed = true;
      if (raf) cancelAnimationFrame(raf);
      container.removeEventListener("scroll", onScroll);
      if (ro) ro.disconnect(); else window.removeEventListener("resize", schedule);
      for (var k in mounted) { try { layer.removeChild(mounted[k].node); } catch (e) {} }
      mounted = Object.create(null);
      try { container.removeChild(layer); } catch (e) {}
      try { container.removeChild(spacer); } catch (e) {}
    }

    // initial paint (after layout is available)
    sync();

    return {
      el: container,
      setTotal: setTotal,
      refresh: refresh,
      scrollToIndex: scrollToIndex,
      destroy: destroy,
      get total() { return total; },
      get rowHeight() { return rowHeight; }
    };
  }

  window.VList = VList;
})();
