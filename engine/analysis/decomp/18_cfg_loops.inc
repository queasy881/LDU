/* 18_cfg_loops.inc -- CFG: dominators, loops, reducibility
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* ---- PROVABLY-CORRECT CFG REDUCIBILITY (Hecht-Ullman T1-T2 interval reduction) ----
     * A flowgraph is REDUCIBLE iff repeated application of
     *   T1: delete a self-loop  (n -> n)
     *   T2: merge a node into its UNIQUE predecessor
     * collapses it to a single node (Hecht & Ullman 1972; Aho/Sethi/Ullman "Dragon"
     * Thm 9.42). Reducibility is a pure property of the CFG built by CfgBuilder,
     * independent of the structurer — so this is ground truth: an IRREDUCIBLE CFG
     * provably has NO goto-free structured form without node-splitting/state-machine
     * duplication, whereas a reducible CFG that still emits gotos is a structurer
     * limitation. Operates only on intra-procedural succ/pred edges restricted to the
     * blocks reachable from the entry. O(V*(V+E)) — trivial at our sizes.
     * Returns true iff reducible. Inert unless called (DS_IRRED_REPORT). */
    bool cfg_is_reducible() const {
        int n = (int)blocks.size();
        if (n <= 1) return true;
        int ent = 0;   /* entry is block id 0 (CfgBuilder seeds leaders with f->rva first) */
        /* reachable set from entry */
        std::vector<char> reach(n, 0);
        { std::vector<int> st{ent}; reach[ent] = 1;
          while (!st.empty()) { int b = st.back(); st.pop_back();
            for (int s : blocks[b].succ) if (s >= 0 && s < n && !reach[s]) { reach[s] = 1; st.push_back(s); } } }
        /* working adjacency as SETS (parallel edges collapse; irrelevant to reducibility) */
        std::vector<std::set<int>> succ(n), pred(n);
        std::vector<char> alive(n, 0); int live = 0;
        for (int b = 0; b < n; ++b) if (reach[b]) { alive[b] = 1; ++live;
            for (int s : blocks[b].succ) if (s >= 0 && s < n && reach[s]) succ[b].insert(s); }
        for (int b = 0; b < n; ++b) if (alive[b]) for (int s : succ[b]) pred[s].insert(b);
        bool changed = true;
        while (changed && live > 1) {
            changed = false;
            /* T1: strip every self-loop first (cheap, exposes T2 merges) */
            for (int b = 0; b < n; ++b) if (alive[b] && succ[b].count(b)) { succ[b].erase(b); pred[b].erase(b); changed = true; }
            if (changed) continue;
            /* T2: fold a non-entry node with a single predecessor into that predecessor */
            for (int b = 0; b < n; ++b) {
                if (!alive[b] || b == ent || pred[b].size() != 1) continue;
                int m = *pred[b].begin();
                if (m == b) continue;
                for (int s : succ[b]) {           /* m absorbs b's out-edges */
                    succ[m].insert(s);
                    pred[s].erase(b); pred[s].insert(m);
                }
                succ[m].erase(b); pred[b].clear(); succ[b].clear();
                alive[b] = 0; --live; changed = true; break;
            }
        }
        return live == 1;
    }

    std::string build_incr(const std::string& iv, char op, int64_t step) {
        if (op == '+' && step < 0) { op = '-'; step = -step; }
        else if (op == '-' && step < 0) { op = '+'; step = -step; }
        if (step == 1) return iv + (op == '+' ? "++" : "--");
        return iv + (op == '+' ? " += " : " -= ") + std::to_string(step);
    }
    /* render a statement as a single inline expression (no indent, no trailing `;`). */
    std::string render_stmt_inline(const Stmt& s) {
        std::string t; int saved = indent_lvl; indent_lvl = 0; emit_stmt(s, t); indent_lvl = saved;
        while (!t.empty() && t.back() == '\n') t.pop_back();
        if (!t.empty() && t.back() == ';') t.pop_back();
        size_t p = t.find_first_not_of(" \t");
        if (p != std::string::npos) t = t.substr(p);
        return t;
    }
    /* is `s` an `IV = IV +/- const` increment? sets iv/op/step. */
    bool match_incr(const Stmt& s, std::string& iv, char& op, int64_t& step) {
        if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) return false;
        ExprP r = s.rhs;
        if (r->kind != EK::Binary || (r->op != "+" && r->op != "-")) return false;
        const std::string nm = s.lhs->name; ExprP a = r->a, b = r->b;
        auto isVar = [&](const ExprP& e){ return e && e->kind == EK::Var && e->name == nm; };
        auto isC   = [&](const ExprP& e){ return e && e->kind == EK::Const && !e->is_float; };
        if (r->op == "+" && isVar(a) && isC(b)) { iv = nm; op = '+'; step = b->cval; return true; }
        if (r->op == "+" && isVar(b) && isC(a)) { iv = nm; op = '+'; step = a->cval; return true; }
        if (r->op == "-" && isVar(a) && isC(b)) { iv = nm; op = '-'; step = b->cval; return true; }
        return false;
    }
    void detect_for_loops() {
        for_of_header.clear(); iv_suppressed_stmts.clear(); induction_var_of_header.clear();
        if (std::getenv("DS_NO_FORLOOP")) return;
        for (auto& kv : loop_of_header) {
            int header = kv.first, lh = kv.second; Loop& lp = loops[lh]; Block& H = blocks[header];
            int follow = loop_follow(header);
            /* MIRROR emit_loop's pretest+header_clean predicate EXACTLY */
            bool pretest = H.ends_jcc && H.cond && (H.taken == follow || H.fall == follow);
            if (!pretest) continue;
            for (auto& s : H.stmts) if (s.kind != SK::Comment) { pretest = false; break; }
            if (!pretest) continue;
            int L = unique_latch(lh, header, follow); if (L < 0) continue;
            /* latch must have exactly ONE meaningful stmt = the IV increment */
            int inc_idx = -1, meaningful = 0; std::string iv; char op = '+'; int64_t step = 0;
            for (size_t i = 0; i < blocks[L].stmts.size(); ++i) {
                if (blocks[L].stmts[i].kind == SK::Comment) continue;
                meaningful++;
                std::string civ; char cop; int64_t cs;
                if (match_incr(blocks[L].stmts[i], civ, cop, cs)) { inc_idx = (int)i; iv = civ; op = cop; step = cs; }
            }
            if (meaningful != 1 || inc_idx < 0) continue;
            /* the exit condition must test the IV */
            bool cond_is_taken = (H.fall == follow);
            ExprP stay = cond_is_taken ? H.cond : negate_expr(H.cond);
            if (!reads_named_var(stay, iv)) continue;
            /* IV must not be mutated anywhere else in the loop body */
            bool bad = false;
            for (int bb : lp.body) {
                for (size_t i = 0; i < blocks[bb].stmts.size(); ++i) {
                    if (bb == L && (int)i == inc_idx) continue;
                    Stmt& s = blocks[bb].stmts[i];
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && s.lhs->name == iv) { bad = true; break; }
                }
                if (bad) break;
            }
            if (bad) continue;
            ForInfo fi; fi.ok = true; fi.iv = iv; fi.op = op; fi.step = step;
            /* init from the preheader = idom[header] (a block outside the loop). Store
             * its location only; render at EMIT time so it goes through autoname too. */
            int pre = (header < (int)idom.size()) ? idom[header] : -1;
            if (pre >= 0 && pre != header && !lp.body.count(pre)) {
                for (int i = (int)blocks[pre].stmts.size() - 1; i >= 0; --i) {
                    Stmt& s = blocks[pre].stmts[i];
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                        s.lhs->name == iv && !has_call(s.rhs)) {
                        fi.init_blk = pre; fi.init_idx = i;
                        iv_suppressed_stmts.insert({pre, i});
                        break;
                    }
                }
            }
            iv_suppressed_stmts.insert({L, inc_idx});
            for_of_header[header] = fi;
            induction_var_of_header[header] = iv;
        }
    }

    /* Semantic naming: alias the single return-value local to `result` and each loop
     * induction var to i/j/k by nest depth. Pure display alias (autoname map); the
     * `used` set guarantees no collision with a param or a live name, and only
     * v<N>/t<N> LOCALS are ever renamed. Runs after detect_for_loops (consumes its
     * induction_var_of_header). Gated by DS_NO_AUTONAME. */
    void compute_autonames() {
        autoname.clear();
        if (std::getenv("DS_NO_AUTONAME")) return;
        std::set<std::string> used;
        for (int i = 0; i < num_params; ++i) used.insert("a" + std::to_string(i + 1));
        std::function<void(const ExprP&)> mark = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Var) used.insert(e->name);
            /* a callee named exactly `i`/`result`/... would be shadowed by a local of
             * that name (a hard error: the call becomes a non-function). Reserve it. */
            if (e->kind == EK::Call && !e->callee.empty()) used.insert(e->callee);
            mark(e->a); mark(e->b); mark(e->c);
            for (auto& a : e->args) mark(a);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { mark(s.lhs); mark(s.rhs); }
            mark(b.cond); mark(b.ret_value); mark(b.ret_raw); mark(b.switch_var); mark(b.tail_call);
        }
        auto is_param = [](const std::string& n){ return n.size() >= 2 && n[0] == 'a' && n[1] >= '1' && n[1] <= '9'; };
        auto is_local = [](const std::string& n){
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) return false;
            for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') return false;
            return true;
        };
        auto assign = [&](const std::string& canon, const std::string& want,
                          const std::vector<std::string>& pool) {
            if (autoname.count(canon) || !is_local(canon)) return;
            std::string pick;
            if (!used.count(want)) pick = want;
            else for (auto& p : pool) if (!used.count(p)) { pick = p; break; }
            if (pick.empty()) return;
            autoname[canon] = pick; used.insert(pick);
        };
        /* (a) result: the single LOCAL flowing to a value return (never a param) */
        if (used_return) {
            std::set<std::string> rets; bool bad = false;
            for (auto& b : blocks) {
                if (!b.has_ret_value || !b.ret_value) continue;
                ExprP r = b.ret_value;
                while (r && r->kind == EK::Cast) r = r->a;
                if (r && r->kind == EK::Var) {
                    if (is_param(r->name)) { bad = true; break; }
                    if (is_local(r->name)) rets.insert(r->name);
                }
            }
            if (!bad && rets.size() == 1) assign(*rets.begin(), "result", {});
        }
        /* (b) induction i/j/k by loop-nest depth (from detect_for_loops) */
        static const std::vector<std::string> POOL = {"i","j","k","l","m","n"};
        std::vector<std::pair<int,std::string>> ivs;
        for (auto& kv : induction_var_of_header) {
            int header = kv.first, depth = 0;
            for (auto& kv2 : loop_of_header)
                if (kv2.first != header && loops[kv2.second].body.count(header)) depth++;
            ivs.push_back({depth, kv.second});
        }
        std::sort(ivs.begin(), ivs.end());
        for (auto& p : ivs) {
            std::string want = (p.first < (int)POOL.size()) ? POOL[p.first] : std::string("i");
            assign(p.second, want, POOL);
        }
        /* (c) NAME A LOCAL AFTER THE API THAT PRODUCED IT.
         *     v7 = CreateFileW(..)      ->  hFile   = CreateFileW(..)
         *     v3 = GetModuleHandleW(..) ->  hModule = GetModuleHandleW(..)
         * The API already told us what the value IS -- propagate_api_types spends that on the
         * TYPE; this spends it on the NAME, which is what the reader actually greps for. It is
         * the same contract, not a new guess, and it is what Hex-Rays does here.
         *
         * Rides the SAME machinery as result/i/j/k: a pure display alias through `autoname`,
         * `used` guarantees no collision with a parameter, a live name or a callee, and only
         * v<N>/t<N> locals are ever renamed. A second CreateFile in one function gets hFile2
         * from the pool rather than shadowing the first.
         * Only APIs whose product has an obvious, conventional name -- an API returning a
         * count or a BOOL is deliberately absent; `v5` beats a wrong name. DS_NO_AUTONAME. */
        struct AN { const char* api; const char* nm; };
        static const AN ANAMES[] = {
            {"GetModuleHandle","hModule"}, {"LoadLibrary","hModule"}, {"LoadLibraryEx","hModule"},
            {"GetProcAddress","pfn"},
            {"CreateFile","hFile"},        {"FindFirstFile","hFind"},
            {"CreateThread","hThread"},    {"OpenThread","hThread"},
            {"CreateMutex","hMutex"},      {"CreateEvent","hEvent"},
            {"CreateSemaphore","hSemaphore"},
            {"OpenProcess","hProcess"},    {"GetCurrentProcess","hProcess"},
            {"GetCurrentThread","hThread"},{"GetStdHandle","hStd"},
            {"CreateToolhelp32Snapshot","hSnap"}, {"GetProcessHeap","hHeap"},
            {"HeapAlloc","pMem"},          {"HeapReAlloc","pMem"},
            {"VirtualAlloc","pMem"},       {"VirtualAllocEx","pMem"},
            {"LocalAlloc","pMem"},         {"GlobalAlloc","pMem"},
            {"MapViewOfFile","pView"},
            {"CreateWindowEx","hWnd"},     {"FindWindow","hWnd"},
            {"GetForegroundWindow","hWnd"},{"GetActiveWindow","hWnd"},
            {"GetDesktopWindow","hWnd"},   {"WindowFromPoint","hWnd"},
            {"GetDC","hdc"},               {"BeginPaint","hdc"},
            {"GetLastError","dwError"},    {"GetTickCount","dwTick"},
            {"GetCurrentProcessId","dwPid"}, {"GetCurrentThreadId","dwTid"},
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
                ExprP r = s.rhs;
                while (r && r->kind == EK::Cast && r->a) r = r->a;
                if (!r || r->kind != EK::Call || r->callee.empty()) continue;
                std::string base = r->callee;                 /* strip the A/W suffix */
                if (base.size() > 1 && (base.back() == 'A' || base.back() == 'W')) {
                    char pc = base[base.size() - 2];
                    if (pc >= 'a' && pc <= 'z') base.pop_back();
                }
                for (const AN& a : ANAMES) {
                    if (base != a.api && r->callee != a.api) continue;
                    std::vector<std::string> pool;            /* hFile2, hFile3, ... */
                    for (int k = 2; k <= 6; ++k) pool.push_back(std::string(a.nm) + std::to_string(k));
                    assign(s.lhs->name, a.nm, pool);
                    break;
                }
            }
        }
    }

    /* D1: TEMP-WIDTH NARROWING via a VALUE-RANGE FIXPOINT (kill `(int)tN` cast noise).
     * A scalar temp declared `long long` (var_width==8) forces `(int)tN` on every 32-bit
     * use. Narrow it to a 32-bit type (keeping signedness) when its VALUE provably fits in
     * 32 bits — then storing 32 bits and re-extending is value-identical, and truncate()
     * stops emitting the (int) framing (the Var node width becomes 4, so `truncate(v,4)`
     * short-circuits). fits32(e) is a monotone fixpoint over the temp defs:
     *   Cast w<=4 -> fits;  Cast w8 -> fits(inner);  Binary/Unary w<=4 -> fits (the op is
     *   32-bit, result wraps to 32);  &|^ w8 -> fits(a)&&fits(b);  >> w8 -> fits(a);
     *   Mem w<=4 -> fits;  Const in [-2^31, 2^31-1];  Call int-return -> fits;  a candidate
     *   Var -> its current fits; a non-candidate Var -> its declared width<=4.
     * A temp is narrowable iff it has >=1 def and EVERY def's rhs fits32. Excludes
     * pointers/floats/addr-taken/arrays/struct-ptrs/conflict-raw. HIGH-RISK (an unsound
     * narrow = silent truncation) — the behavioral corpus (50k random+edge inputs incl.
     * large/negative values) is the backstop; a failure is FIXED (tighten fits32), not
     * reverted. Gated DS_NO_NARROW. */
    void narrow_temp_widths() {
        if (std::getenv("DS_NO_NARROW")) return;
        std::set<std::string> addr; collect_addr_taken(addr);
        std::set<std::string> cand;
        std::map<std::string,int> defs;
        for (auto& b : blocks) for (auto& s : b.stmts)
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) defs[s.lhs->name]++;
        for (auto& kv : var_width) {
            const std::string& n = kv.first;
            if (kv.second != 8 || defs[n] < 1) continue;
            if ((var_pointer.count(n) && var_pointer[n]) || (var_is_float.count(n) && var_is_float[n])) continue;
            if (addr.count(n) || array_locals.count(n) || conflict_raw_vars.count(n) || param_structs.count(n)) continue;
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) continue;
            bool dig = true; for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') { dig = false; break; }
            if (dig) cand.insert(n);
        }
        if (cand.empty()) return;
        /* A candidate whose EVERY explicit def reads ITSELF (`v = f(v)`, e.g. a loop-carried
         * `v = (ull)v >> 8`) has an IMPLICIT initial value from OUTSIDE the SK::Assigns — a
         * param-home alias like `v = a1` that is materialized only as the decl initializer,
         * not a stmt. The fixpoint can't width-check that hidden init, so narrowing would
         * truncate a 64-bit initial value (byte_swap64/varint: v holds the 64-bit param).
         * Require >=1 ROOT def (an SK::Assign whose rhs does NOT read v) — its width IS
         * checked by the fixpoint. */
        {
            std::set<std::string> has_root;
            for (auto& b : blocks) for (auto& s : b.stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && cand.count(s.lhs->name) &&
                    count_var_reads(s.rhs, s.lhs->name) == 0)
                    has_root.insert(s.lhs->name);
            for (auto it = cand.begin(); it != cand.end(); )
                if (!has_root.count(*it)) it = cand.erase(it); else ++it;
            if (cand.empty()) return;
        }
        std::map<std::string,char> fits; for (auto& n : cand) fits[n] = 1;
        std::function<bool(const ExprP&)> f32 = [&](const ExprP& e) -> bool {
            if (!e) return true;
            switch (e->kind) {
                case EK::Const: return e->cval >= -0x80000000LL && e->cval <= 0x7FFFFFFFLL;
                case EK::Cast:  return e->width <= 4 ? true : f32(e->a);
                case EK::Var: {
                    if (cand.count(e->name)) return fits[e->name];
                    auto it = var_width.find(e->name);
                    return (it != var_width.end() ? it->second : 8) <= 4;
                }
                case EK::Mem:   return e->width > 0 && e->width <= 4;
                case EK::Unary: return e->width > 0 && e->width <= 4 ? true : f32(e->a);
                case EK::Binary: {
                    if (e->width > 0 && e->width <= 4) return true;
                    const std::string& op = e->op;
                    if (op == "&" || op == "|" || op == "^") return f32(e->a) && f32(e->b);
                    if (op == ">>") return f32(e->a);
                    return false;
                }
                case EK::Ternary: return f32(e->b) && f32(e->c);
                case EK::Call:  return e->ret_kind == 1;   /* int-return call */
                default: return false;
            }
        };
        bool changed = true; int guard = 0;
        while (changed && guard++ < 24) {
            changed = false;
            std::map<std::string,char> nf; for (auto& n : cand) nf[n] = 1;
            for (auto& b : blocks) for (auto& s : b.stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && cand.count(s.lhs->name))
                    if (!f32(s.rhs)) nf[s.lhs->name] = 0;
            for (auto& n : cand) if (nf[n] != fits[n]) { fits[n] = nf[n]; changed = true; }
        }
        std::set<std::string> narrow;
        for (auto& n : cand) if (fits[n]) narrow.insert(n);
        if (narrow.empty()) return;
        std::function<void(const ExprP&)> setw = [&](const ExprP& e){
            if (!e) return;
            if (e->kind == EK::Var && narrow.count(e->name)) e->width = 4;
            setw(e->a); setw(e->b); setw(e->c); for (auto& ar : e->args) setw(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { setw(s.lhs); setw(s.rhs); }
            setw(b.cond); setw(b.ret_value); setw(b.ret_raw); setw(b.switch_var); setw(b.tail_call);
        }
        for (auto& n : narrow) { var_width[n] = 4; var_is_ll.erase(n); }
    }

    /* H1: FINAL DISPLAY RENUMBER (Hex-Rays naming). Our lifter leaks raw non-contiguous
     * internal SSA counter values (t481, v519) and splits locals across TWO prefixes
     * (v#/t#). Hex-Rays renumbers each function's locals to a contiguous `v1, v2, …` in
     * first-appearance order. This is a pure DISPLAY alias (added to `autoname`; the
     * canonical Expr::name is untouched, so all analysis and every gate is unaffected).
     * Runs AFTER compute_autonames so result/i/j/k keep their semantic names and only
     * the anonymous temps get renumbered. Gated DS_NO_RENUM. */
    void compute_display_renumber() {
        if (std::getenv("DS_NO_RENUM")) return;
        std::set<std::string> reserved;
        for (int i = 0; i < num_params; ++i) reserved.insert("a" + std::to_string(i + 1));
        for (auto& kv : autoname) reserved.insert(kv.second);   /* result / i / j / k */
        std::function<void(const ExprP&)> mcall = [&](const ExprP& e){
            if (!e) return;
            if (e->kind == EK::Call && !e->callee.empty()) reserved.insert(e->callee);
            mcall(e->a); mcall(e->b); mcall(e->c); for (auto& a : e->args) mcall(a);
        };
        for (auto& b : blocks) { for (auto& s : b.stmts) { mcall(s.lhs); mcall(s.rhs); }
            mcall(b.cond); mcall(b.ret_value); mcall(b.ret_raw); mcall(b.switch_var); mcall(b.tail_call); }
        auto renumberable = [&](const std::string& n)->bool {
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) return false;   /* v# / t# scalars */
            for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') return false;
            return !autoname.count(n) && !array_locals.count(n);
        };
        std::vector<std::string> order; std::set<std::string> seen;
        std::function<void(const ExprP&)> walk = [&](const ExprP& e){
            if (!e) return;
            if (e->kind == EK::Var && renumberable(e->name) && !seen.count(e->name)) {
                seen.insert(e->name); order.push_back(e->name);
            }
            walk(e->a); walk(e->b); walk(e->c); for (auto& a : e->args) walk(a);
        };
        std::vector<int> border;
        for (auto& b : blocks) border.push_back(b.id);
        if (!rpo_num.empty()) std::sort(border.begin(), border.end(), [&](int x, int y){
            int rx = (size_t)x < rpo_num.size() ? rpo_num[x] : (1<<30);
            int ry = (size_t)y < rpo_num.size() ? rpo_num[y] : (1<<30);
            return rx < ry; });
        for (int id : border) { Block& b = blocks[id];
            for (auto& s : b.stmts) { walk(s.lhs); walk(s.rhs); }
            walk(b.cond); walk(b.ret_value); walk(b.ret_raw); walk(b.switch_var); walk(b.tail_call); }
        int ctr = 1;
        for (auto& nm : order) {
            std::string nn;
            do { nn = "v" + std::to_string(ctr++); } while (reserved.count(nn));
            autoname[nm] = nn; reserved.insert(nn);
        }
    }

    /* forward reachability over succ edges (from -> to), excluding merged blocks. */
    bool can_reach(int from, int to) {
        if (from < 0 || to < 0) return false;
        if (from == to) return true;
        std::vector<char> seen(blocks.size(), 0);
        std::vector<int> work{from}; seen[from] = 1;
        while (!work.empty()) {
            int u = work.back(); work.pop_back();
            for (int s : blocks[u].succ) {
                if (s < 0 || (size_t)s >= blocks.size() || seen[s] || merged_blocks.count(s)) continue;
                if (s == to) return true;
                seen[s] = 1; work.push_back(s);
            }
        }
        return false;
    }

    /* ---- Node-splitting for compiler-ROTATED (irreducible) loops ----
     * MSVC emits a guarded loop as a two-entry (irreducible) cycle: block K ends in an
     * UNCONDITIONAL jump to a header H, where H reaches K (a back-edge) but does NOT
     * dominate K, so find_loops rejects it and the structurer must `goto`. PEEL H:
     * duplicate it for the loop's out-of-cycle (guard) entries. H is then reachable
     * ONLY through the back-edge, the cycle becomes single-entry / reducible, and the
     * existing structurer emits a clean `while(true){ ...; body_A }` with the first
     * body_A peeled ahead of it. Behavior-preserving: H's statements are duplicated,
     * no edge SEMANTICS change. Bounded by a peel budget to cap duplication/bloat. */
    int rotpeel_budget = 40;
    /* Tarjan SCCs (iterative — huge functions would blow a recursive stack). Returns
     * only NON-trivial SCCs (a real cycle: >1 block, or a self-loop). */
    std::vector<std::vector<int>> compute_sccs() {
        int n = (int)blocks.size();
        std::vector<int> idx(n, -1), low(n, 0), onstk(n, 0);
        std::vector<int> stk; std::vector<std::vector<int>> sccs; int counter = 0;
        for (int s = 0; s < n; ++s) {
            if (idx[s] != -1 || merged_blocks.count(s)) continue;
            std::vector<std::pair<int,size_t>> call;
            idx[s] = low[s] = counter++; stk.push_back(s); onstk[s] = 1; call.push_back({s, 0});
            while (!call.empty()) {
                int u = call.back().first; size_t& i = call.back().second;
                if (i < blocks[u].succ.size()) {
                    int v = blocks[u].succ[i++];
                    if (v < 0 || (size_t)v >= blocks.size() || merged_blocks.count(v)) continue;
                    if (idx[v] == -1) { idx[v]=low[v]=counter++; stk.push_back(v); onstk[v]=1; call.push_back({v,0}); }
                    else if (onstk[v]) low[u] = std::min(low[u], idx[v]);
                } else {
                    if (low[u] == idx[u]) {
                        std::vector<int> comp;
                        while (true) { int w=stk.back(); stk.pop_back(); onstk[w]=0; comp.push_back(w); if (w==u) break; }
                        bool self=false; if (comp.size()==1) for (int su:blocks[comp[0]].succ) if (su==comp[0]) self=true;
                        if (comp.size() > 1 || self) sccs.push_back(comp);
                    }
                    call.pop_back();
                    if (!call.empty()) low[call.back().first] = std::min(low[call.back().first], low[u]);
                }
            }
        }
        return sccs;
    }
    void split_rotated_loops() {
        for (int iter = 0; iter < 120 && rotpeel_budget > 0; ++iter) {
            rebuild_edges();
            auto sccs = compute_sccs();
            int done = -1;
            /* A MULTI-ENTRY SCC is irreducible: >1 block in the cycle is reached from
             * OUTSIDE the cycle (the compiler's guard path enters mid-loop). Peel the
             * smallest secondary entry: the copy Mp runs M's statements once then flows
             * to M's own successors (which include the edge back toward the primary
             * entry), so the external path joins the cycle at the primary entry and M is
             * left reachable only from inside. Repeat until the SCC is single-entry =>
             * reducible => find_loops sees a natural loop => structurer emits `while`. */
            for (auto& scc : sccs) {
                std::set<int> body(scc.begin(), scc.end());
                std::vector<int> entries;
                for (int m : scc)
                    for (int p : blocks[m].pred)
                        if (!body.count(p)) { entries.push_back(m); break; }
                if (entries.size() < 2) continue;           /* single-entry: reducible already */
                int Msel = -1, bestn = 1 << 30;
                for (int m : entries) {
                    Block& MB = blocks[m];
                    if (MB.is_switch || MB.is_switch_guard) continue;
                    int nst = 0; for (auto& s : MB.stmts) if (s.kind != SK::Comment) nst++;
                    if (nst > 12) continue;
                    if (nst < bestn) { bestn = nst; Msel = m; }
                }
                if (Msel < 0) continue;
                std::vector<int> ext;
                for (int p : blocks[Msel].pred) if (!body.count(p)) ext.push_back(p);
                Block cpy = blocks[Msel];
                cpy.id = (int)blocks.size(); cpy.succ.clear(); cpy.pred.clear();
                int Mp = cpy.id;
                blocks.push_back(std::move(cpy));
                for (int g : ext) {
                    Block& G = blocks[g];
                    if (G.taken == Msel) G.taken = Mp;
                    if (G.fall == Msel)  G.fall  = Mp;
                    for (auto& s : G.case_succ) if (s == Msel) s = Mp;
                    if (G.default_succ == Msel) G.default_succ = Mp;
                }
                rotpeel_budget--; done = Msel; break;
            }
            if (done < 0) break;
        }
        rebuild_edges();
    }

    /* =================================================================== */
    /*  6+7. Structuring + emission                                         */
    /* =================================================================== */

    std::string out;
    int indent_lvl = 1;
    std::set<int> emitted;
    std::set<int> need_label;
    std::set<int> merged_blocks;   /* blocks folded into a predecessor by short-circuit merge */

    bool block_stmts_empty(int id) {
        for (auto& s : blocks[id].stmts) if (s.kind != SK::Comment) return false;
        return true;
    }
    /* Recompute succ/pred from the terminators, skipping merged-away blocks. */
    void rebuild_edges() {
        for (auto& b : blocks) { b.succ.clear(); b.pred.clear(); }
        for (auto& b : blocks) {
            if (merged_blocks.count(b.id)) continue;
            std::set<int> added;
            auto addedge = [&](int s) {
                if (s < 0 || (size_t)s >= blocks.size() || merged_blocks.count(s) || added.count(s)) return;
                added.insert(s); b.succ.push_back(s); blocks[s].pred.push_back(b.id);
            };
            if (b.is_switch) { for (int s : b.case_succ) addedge(s); if (b.default_succ >= 0) addedge(b.default_succ); }
            else { if (b.taken >= 0) addedge(b.taken); if (b.fall >= 0) addedge(b.fall); }
        }
    }

    /* ---------- TAIL MERGING (cross-jumping) ----------
     * The /O2 compiler routinely DUPLICATES a shared tail — a `grow; append;
     * return` epilogue, a `set *a1; optionally set *a2; return` landing — into
     * every path, so the binary's CFG holds N byte-identical terminal blocks.
     * The readability analysis flagged this repeatedly as "the same 4-6 line
     * tail duplicated 3-6x" (fun_0001c930 / 00013490 / 00020530). Merge every
     * group of identical terminal blocks into ONE canonical copy: redirect each
     * edge into a duplicate to the canonical block and retire the duplicate.
     * The structurer then emits the tail once; the extra entrants fall through
     * or `goto` it — the Hex-Rays shared-epilogue form.
     *
     * ALWAYS behavior-preserving (the cross-jumping theorem): the merged block's
     * statements act on runtime variable *values* that each predecessor computes
     * BEFORE the jump, so one shared copy returns/does exactly what each path set
     * up. reg_out equality on the return registers guards the one case that is
     * NOT a pure runtime value — a return value that is a concrete per-path
     * expression (`return 5` vs `return 7`) never compares equal, so it is left
     * duplicated. */
    bool tm_stmt_eq(const Stmt& x, const Stmt& y) {
        if (x.kind != y.kind || x.ret_void != y.ret_void) return false;
        if ((bool)x.lhs != (bool)y.lhs || (bool)x.rhs != (bool)y.rhs) return false;
        if (x.lhs && !exprEqual(x.lhs, y.lhs)) return false;
        if (x.rhs && !exprEqual(x.rhs, y.rhs)) return false;
        return true;
    }
    bool tm_tail_eq(int x, int y) {
        Block& X = blocks[x]; Block& Y = blocks[y];
        if (!X.ends_ret || !Y.ends_ret) return false;       /* terminal-return only  */
        if (X.ends_jcc || Y.ends_jcc || X.is_switch || Y.is_switch) return false;
        if (X.stmts.size() != Y.stmts.size()) return false;
        if (X.stmts.size() < 2) return false;               /* a bare `return` stays duplicated */
        for (size_t i = 0; i < X.stmts.size(); ++i)
            if (!tm_stmt_eq(X.stmts[i], Y.stmts[i])) return false;
        /* identical returned value on every return-carrying register */
        for (int r : { R_RAX, R_RDX, R_XMM0, R_XMM1 }) {
            ExprP xr = X.reg_out[r], yr = Y.reg_out[r];
            if ((bool)xr != (bool)yr) return false;
            if (xr && !exprEqual(xr, yr)) return false;
        }
        return true;
    }
    std::set<int> tail_merge_targets;   /* canonical blocks that absorbed a duplicate tail */
    void merge_identical_tails() {
        tail_merge_targets.clear();
        if (std::getenv("DS_NO_TAILMERGE")) return;
        if (std::getenv("DS_DBG_TM") && f) {
            rebuild_edges();
            fprintf(stderr, "[TM] fn %llx: %zu blocks\n", (unsigned long long)f->rva, blocks.size());
            for (auto& b : blocks) {
                fprintf(stderr, "  blk %d (0x%llx) ret=%d jmp=%d jcc=%d sw=%d taken=%d fall=%d stmts=%zu preds=[",
                        b.id, (unsigned long long)b.addr, b.ends_ret, b.ends_jmp, b.ends_jcc, b.is_switch, b.taken, b.fall,
                        b.stmts.size());
                for (int p : b.pred) fprintf(stderr, "%d ", p);
                fprintf(stderr, "]\n");
            }
        }
        for (int pass = 0; pass < 8; ++pass) {
            rebuild_edges();
            bool changed = false;
            for (int i = 0; i < (int)blocks.size(); ++i) {
                if (merged_blocks.count(i) || !blocks[i].ends_ret) continue;
                if (i != 0 && blocks[i].pred.empty()) continue;      /* unreachable */
                for (int j = i + 1; j < (int)blocks.size(); ++j) {
                    if (merged_blocks.count(j) || !blocks[j].ends_ret) continue;
                    if (j != 0 && blocks[j].pred.empty()) continue;
                    if (!tm_tail_eq(i, j)) continue;
                    for (auto& P : blocks) {                          /* redirect edges j -> i */
                        if (P.taken == j) P.taken = i;
                        if (P.fall == j) P.fall = i;
                        if (P.default_succ == j) P.default_succ = i;
                        for (int& c : P.case_succ) if (c == j) c = i;
                    }
                    merged_blocks.insert(j);
                    tail_merge_targets.insert(i);
                    changed = true;
                }
            }
            if (!changed) break;
        }
        rebuild_edges();
        if (std::getenv("DS_DBG_TM") && f && !tail_merge_targets.empty())
            fprintf(stderr, "[TM] fn %llx merged into %zu canonical tail(s)\n",
                    (unsigned long long)f->rva, tail_merge_targets.size());
    }

    /* ---------- FLAG-DISPATCH for MULTI-EXIT LOOPS ----------
     * A natural loop with TWO exit targets (the follow F + one secondary S, where
     * S is a forward join reached from OUTSIDE the loop too — a pre-loop guard)
     * cannot be structured goto-free by post-dominator rules: S is not a post-dom
     * of any single branch, so the structurer emits S in one path and `goto`s it
     * from the loop's break (fun_0001ab40's residual gotos).
     *
     * Fix (the Boehm-Jacopini flag construction, minimal duplication — one int):
     * route EVERY edge into S, and the loop's primary-exit edge into F, through a
     * single synthetic dispatch block P that branches on a fresh flag `f`:
     *     f = 0 (entry);  every "go to S" edge sets f = 1;  P: if (f) -> S else -> F.
     * Now S has exactly ONE predecessor (P) so it is emitted ONCE, and the loop is
     * single-exit (-> P). The structurer then produces pure if/while, zero gotos.
     * Behaviour-preserving: f exactly records which exit was taken. */
    void flag_dispatch_multiexit_loops() {
        if (std::getenv("DS_NO_FLAG_DISPATCH")) return;
        fwd_sinks.clear();
        loop_fwd_sink.clear();
        /* exits: empty => 2-way plan (F,S); else N-way ([J, T1, T2, ...] dispatched via
         * an if-ladder on the flag). */
        struct Plan { int H, F, S; std::set<int> body; std::vector<int> exits; };
        /* FIXPOINT: nested/sequential joins (25->38 in fn_00015c20) overlap within a
         * single pass, so one is claimed and the other skipped. Iterate: apply a
         * round, recompute the CFG, then re-detect the now-exposed joins. */
        for (int pass = 0; pass < 12; ++pass) {
        std::vector<Plan> plans;
        std::set<int> touched;   /* blocks already claimed by a plan (avoid overlap) */
        for (auto& kv : loop_of_header) {
            int H = kv.first;
            if (H < 0 || H >= (int)blocks.size()) continue;
            Loop& lp = loops[kv.second];
            int F = loop_follow(H);
            if (F < 0 || F >= (int)blocks.size()) continue;
            std::set<int> exits;
            for (int bl : lp.body)
                for (int s : blocks[bl].succ)
                    if (!lp.body.count(s)) exits.insert(s);
            if (exits.size() != 2 || !exits.count(F)) continue;
            int S = -1; for (int e : exits) if (e != F) S = e;
            if (S < 0 || S == H || S >= (int)blocks.size()) continue;
            if ((int)blocks[S].pred.size() < 2) continue;        /* not a shared join */
            if (loop_of_header.count(S) || loop_of_header.count(F)) continue;
            if (blocks[S].pred.size() > 4 || blocks[F].pred.size() > 4) continue;
            /* skip if any body block is already claimed (nested / overlapping) */
            bool overlap = false;
            for (int bl : lp.body) if (touched.count(bl)) { overlap = true; break; }
            if (overlap || touched.count(S) || touched.count(F)) continue;
            for (int bl : lp.body) touched.insert(bl);
            touched.insert(S); touched.insert(F);
            plans.push_back({H, F, S, lp.body});
        }
        /* FORWARD 2-EXIT REGIONS (non-loop): an OR-chain `if(c1)J; else if(c2)J; ...
         * else T` converges at a shared join J (blk 25 in fn_00015c20, 8 preds) with
         * a single fall-through exit T. Same machinery as the loop case — J is the
         * shared exit (S), T the follow (F), the region R the "body". Only fires with
         * DS_FWD_DISPATCH until proven, and under tight guards (bounded region, exactly
         * 2 exits) to keep the blast radius small. */
        if (!std::getenv("DS_NO_FWD_DISPATCH")) {
            auto idom_lca = [&](int a, int b)->int {
                std::set<int> anc; int x=a, g=0;
                while (x>=0 && g++<100000){ anc.insert(x); if(idom[x]==x||idom[x]<0) break; x=idom[x]; }
                int y=b; g=0;
                while (y>=0 && g++<100000){ if(anc.count(y)) return y; if(idom[y]==y||idom[y]<0) break; y=idom[y]; }
                return -1;
            };
            bool DBGF = std::getenv("DS_DBG_FWD") && f;
            for (int J = 0; J < (int)blocks.size(); ++J) {
                if (loop_of_header.count(J)) continue;
                if ((int)blocks[J].pred.size() < 3) continue;
                if (touched.count(J)) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) touched\n",J,(unsigned long long)blocks[J].addr); continue; }
                /* innermost loop containing J (or -1). An in-loop join is NOT rejected — instead the
                 * loop's continue/break are filtered from its region exits, and if J is the loop's
                 * forward convergence it becomes a loop-forward-sink (emitted once, non-duplicating). */
                int jloop = -1; size_t jbody = SIZE_MAX;
                for (auto& kv2 : loop_of_header)
                    if (loops[kv2.second].body.count(J) && loops[kv2.second].body.size() < jbody) {
                        jloop = kv2.first; jbody = loops[kv2.second].body.size();
                    }
                /* COST GUARD: the region R computation below is O(N) block_reaches per block; running it
                 * for the many convergences of a big loop is O(loop_joins * N^2) and stalls the dump.
                 * Skip in-loop detection for large loops/functions (they keep a few gotos — acceptable). */
                if (jloop >= 0 && (jbody > 48 || (int)blocks.size() > 160)) {
                    if (DBGF) fprintf(stderr,"[FWDREJ] J=%d in_loop bigloop(%zu)/bigfn(%zu)\n",J,jbody,blocks.size());
                    continue;
                }
                /* preds may reach J via taken OR the region's fall-through terminal.
                 * The 2-exit-region check below is the real guard (a plain diamond has
                 * ONE exit and is skipped); require >=2 taken-arms so it is a genuine
                 * convergence, not a single fall edge. */
                bool ok = true;
                int taken_arms = 0;
                for (int p : blocks[J].pred) if (blocks[p].taken == J) ++taken_arms;
                if (taken_arms < 2) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) taken_arms=%d\n",J,(unsigned long long)blocks[J].addr,taken_arms); continue; }
                int E = blocks[J].pred[0];
                for (size_t i = 1; i < blocks[J].pred.size(); ++i) { E = idom_lca(E, blocks[J].pred[i]); if (E < 0) break; }
                if (E < 0 || E == J || !dominates(E, J)) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) E=%d bad\n",J,(unsigned long long)blocks[J].addr,E); continue; }
                /* region R = blocks dominated by E that reach J but are not J and not dominated by J.
                 * "reaches J" is one backward BFS from J (O(N+E)) instead of block_reaches per block
                 * (which was O(N^2) per join and stalled the dump once in-loop joins were included). */
                std::set<int> reachesJ;
                { std::vector<int> wk{J};
                  while (!wk.empty()) { int c = wk.back(); wk.pop_back();
                      for (int p : blocks[c].pred) if (p >= 0 && reachesJ.insert(p).second) wk.push_back(p); } }
                std::set<int> R;
                for (int X : reachesJ) {
                    if (X == J) continue;
                    if (!dominates(E, X)) continue;
                    if (dominates(J, X)) continue;
                    R.insert(X);
                    if (R.size() > 24) { ok = false; break; }
                }
                if (!ok || R.size() < 3) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) Rsize=%zu ok=%d\n",J,(unsigned long long)blocks[J].addr,R.size(),(int)ok); continue; }
                /* collect the distinct exits of R besides J */
                std::vector<int> Ts; bool toomany = false;
                for (int X : R) {
                    for (int s : blocks[X].succ) {
                        if (s == J || R.count(s)) continue;
                        bool seen = false; for (int t : Ts) if (t == s) { seen = true; break; }
                        if (!seen) Ts.push_back(s);
                        if (Ts.size() > 3) { toomany = true; break; }
                    }
                    if (toomany) break;
                }
                /* IN-LOOP forward sink: the loop's continue (header) and break (follow) are loop
                 * control, not region exits — filter them from Ts. If nothing else remains, J is the
                 * loop's forward CONVERGENCE: emit it ONCE at the loop-body level so the nested arms
                 * fall through (zero gotos, zero code duplication). This closes the dominant `in_loop`
                 * goto bucket. Only one per loop (the outermost / most-preds convergence). */
                if (jloop >= 0) {
                    if (std::getenv("DS_NO_LOOP_SINK")) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d in_loop(off)\n",J); continue; }
                    int jfollow = loop_follow(jloop);
                    std::vector<int> Ts2;
                    for (int t : Ts) if (t != jloop && t != jfollow) Ts2.push_back(t);
                    if (!Ts2.empty()) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d in_loop realexits=%zu\n",J,Ts2.size()); continue; }
                    if (touched.count(J)) continue;
                    /* Do NOT mark R touched (unlike the non-loop plans): sequential in-loop convergences
                     * J1->J2 in the same loop have OVERLAPPING regions (R2 contains R1) and BOTH should
                     * become sinks (a fall-through chain). Only claim J so a plan can't re-use it. */
                    loop_fwd_sink[jloop].insert(J); touched.insert(J);
                    if (DBGF) fprintf(stderr,"[LOOPSINK] loop hdr=%d J=%d Rsize=%zu\n",jloop,J,R.size());
                    continue;
                }
                if (Ts.empty()) {
                    /* T=-1 pure convergence: forward SINK (emit once after the region). */
                    if (!std::getenv("DS_NO_FWD_SINK")) fwd_sinks.insert(J);
                    continue;
                }
                if (toomany) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) toomany_exits\n",J,(unsigned long long)blocks[J].addr); continue; }
                bool badexit = false;
                for (int t : Ts) if (t == J || R.count(t) || loop_of_header.count(t)) badexit = true;
                if (badexit) { if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) badexit\n",J,(unsigned long long)blocks[J].addr); continue; }
                bool overlap = touched.count(J);
                for (int t : Ts) if (touched.count(t)) overlap = true;
                for (int X : R) if (touched.count(X)) overlap = true;
                if (overlap) continue;
                if (Ts.size() == 1) {
                    for (int X : R) touched.insert(X);
                    touched.insert(J); touched.insert(Ts[0]);
                    plans.push_back({E, Ts[0], J, R, {}});          /* 2-way (F=T, S=J) */
                } else if (!std::getenv("DS_NO_NWAY")) {
                    for (int X : R) touched.insert(X);
                    touched.insert(J); for (int t : Ts) touched.insert(t);
                    std::vector<int> ex; ex.push_back(J); for (int t : Ts) ex.push_back(t);
                    plans.push_back({E, -1, -1, R, ex});            /* N-way (if-ladder) */
                } else {
                    if (DBGF) fprintf(stderr,"[FWDREJ] J=%d(0x%llx) gt2_exits(%zu) DS_NWAY off\n",J,(unsigned long long)blocks[J].addr,Ts.size()+1);
                    continue;
                }
            }
        }
        if (plans.empty()) break;
        if (std::getenv("DS_DBG_FLAG") && f)
            for (auto& pl : plans) {
                if (!pl.exits.empty()) { fprintf(stderr, "[FLAG] fn %llx N-WAY H=%d exits=%zu\n", (unsigned long long)f->rva, pl.H, pl.exits.size()); continue; }
                fprintf(stderr, "[FLAG] fn %llx loop H=%d(0x%llx) F=%d(0x%llx) S=%d(0x%llx) Spreds=%zu\n",
                        (unsigned long long)f->rva, pl.H, (unsigned long long)blocks[pl.H].addr,
                        pl.F, (unsigned long long)blocks[pl.F].addr, pl.S, (unsigned long long)blocks[pl.S].addr,
                        blocks[pl.S].pred.size());
            }
        for (auto& pl : plans) {
            std::string fv = "t" + std::to_string(++temp_seq);
            var_width[fv] = 4;
            /* ---- N-WAY dispatch: exits [J, T1, ...] via an if-ladder on the flag ---- */
            if (!pl.exits.empty()) {
                int n = (int)pl.exits.size();
                auto split_forN = [&](int T) {
                    std::vector<int> preds = blocks[T].pred;
                    for (int X : preds) {
                        if (X < 0 || X >= (int)blocks.size()) continue;
                        if (pl.body.count(X) || dominates(X, pl.H)) continue;
                        int Tc = (int)blocks.size();
                        Block cp = blocks[T]; cp.id = Tc; cp.pred.clear(); cp.succ.clear();
                        blocks.push_back(cp);
                        Block& XB = blocks[X];
                        if (XB.taken == T) XB.taken = Tc;
                        if (XB.fall == T) XB.fall = Tc;
                        if (XB.default_succ == T) XB.default_succ = Tc;
                        for (int& c : XB.case_succ) if (c == T) c = Tc;
                    }
                };
                for (int e : pl.exits) split_forN(e);
                { Stmt s0; s0.kind = SK::Assign; s0.lhs = mkVar(fv,4); s0.rhs = mkConst(0,4);
                  blocks[0].stmts.insert(blocks[0].stmts.begin(), s0); }
                int P0 = (int)blocks.size();
                std::vector<int> Pids; for (int k = 0; k < n-1; ++k) Pids.push_back(P0 + k);
                for (int k = 0; k < n-1; ++k) {
                    Block pb; pb.id = Pids[k]; pb.addr = blocks[pl.exits[0]].addr;
                    pb.ends_jcc = true;
                    pb.cond = mkBinary("==", mkVar(fv,4), mkConst(k,4), 4);
                    pb.taken = pl.exits[k];
                    pb.fall = (k < n-2) ? Pids[k+1] : pl.exits[n-1];
                    blocks.push_back(pb);
                }
                int ebase = (int)blocks.size();
                std::vector<Block> Es;
                auto routeN = [&](int& edge) {
                    for (int k = 0; k < n; ++k) if (edge == pl.exits[k]) {
                        if (k == 0) { edge = P0; }   /* f=0 default */
                        else {
                            int Eid = ebase + (int)Es.size();
                            Block eb; eb.id = Eid; eb.addr = blocks[pl.exits[k]].addr;
                            eb.ends_jmp = true; eb.taken = P0; eb.fall = -1;
                            Stmt s1; s1.kind = SK::Assign; s1.lhs = mkVar(fv,4); s1.rhs = mkConst(k,4);
                            eb.stmts.push_back(s1);
                            Es.push_back(eb);
                            edge = Eid;
                        }
                        return;
                    }
                };
                int nb = ebase;
                for (int i = 0; i < nb; ++i) {
                    bool isP = false; for (int pid : Pids) if (i == pid) { isP = true; break; }
                    if (isP) continue;
                    Block& X = blocks[i];
                    routeN(X.taken); routeN(X.fall); routeN(X.default_succ);
                    for (int& c : X.case_succ) routeN(c);
                }
                for (auto& e : Es) blocks.push_back(e);
                continue;
            }
            /* NODE-SPLIT the exit targets for their POST-LOOP preds. An exit target
             * (F or S) reached from a block that is neither in the loop nor a guard
             * (a block AFTER the loop, e.g. loop 162's 167<-166 where 166 lives in
             * F=165's body) cannot be routed through the dispatch — that forms a
             * false cycle dispatch->F->...->166->dispatch. Give each such pred its
             * OWN copy of the target (behaviour-identical straight-line block) so the
             * target is left reached ONLY from the loop body + guards. */
            auto split_for = [&](int T) {
                std::vector<int> preds = blocks[T].pred;   /* snapshot */
                for (int X : preds) {
                    if (X < 0 || X >= (int)blocks.size()) continue;
                    if (pl.body.count(X)) continue;                 /* loop edge -> route */
                    if (dominates(X, pl.H)) continue;               /* guard    -> route */
                    int Tc = (int)blocks.size();
                    Block cp = blocks[T];
                    cp.id = Tc; cp.pred.clear(); cp.succ.clear();
                    blocks.push_back(cp);
                    Block& XB = blocks[X];
                    if (XB.taken == T) XB.taken = Tc;
                    if (XB.fall == T) XB.fall = Tc;
                    if (XB.default_succ == T) XB.default_succ = Tc;
                    for (int& c : XB.case_succ) if (c == T) c = Tc;
                }
            };
            split_for(pl.S);
            split_for(pl.F);
            int P = (int)blocks.size();
            Block post;
            post.id = P; post.addr = blocks[pl.S].addr;
            post.ends_jcc = true; post.cond = mkVar(fv, 4);
            post.taken = pl.S; post.fall = pl.F;
            /* f = 0 at function entry */
            { Stmt s0; s0.kind = SK::Assign; s0.lhs = mkVar(fv, 4); s0.rhs = mkConst(0, 4);
              blocks[0].stmts.insert(blocks[0].stmts.begin(), s0); }
            /* every edge X->S becomes X->(f=1; ->P); split conditional edges via a
             * tiny synthetic block so f=1 lands ONLY on the S-bound path. */
            int nblk = (int)blocks.size() + 1;   /* P not pushed yet; account below */
            std::vector<Block> newblocks;
            /* route EVERY edge to S through a tiny (f=1)->P block, and EVERY edge to
             * F straight to P (f stays 0). This makes BOTH S and F single-predecessor
             * (their only pred is P), so each is emitted ONCE and P's two arms
             * reconverge at the real join with zero gotos — even when F itself was a
             * shared join (a sibling branch also reached it). */
            auto redirect_edge = [&](int& edge) {
                if (edge == pl.S) {
                    int E = nblk + (int)newblocks.size();
                    Block eb; eb.id = E; eb.addr = blocks[pl.S].addr;
                    eb.ends_jmp = true; eb.taken = P; eb.fall = -1;
                    Stmt s1; s1.kind = SK::Assign; s1.lhs = mkVar(fv, 4); s1.rhs = mkConst(1, 4);
                    eb.stmts.push_back(s1);
                    newblocks.push_back(eb);
                    edge = E;
                } else if (edge == pl.F) {
                    edge = P;
                }
            };
            int nb = (int)blocks.size();
            for (int i = 0; i < nb; ++i) {
                Block& X = blocks[i];
                redirect_edge(X.taken);
                redirect_edge(X.fall);
                redirect_edge(X.default_succ);
                for (int& c : X.case_succ) redirect_edge(c);
            }
            blocks.push_back(post);
            for (auto& e : newblocks) blocks.push_back(e);
        }
        rebuild_edges();
        compute_dominators();
        compute_postdom();
        find_loops();
        }   /* end fixpoint pass loop */
    }

    /* Combine short-circuit condition chains into ONE predicate so the structurer
     * sees `if (c1 && c2 && ...)` instead of a chain of guards each branching to a
     * shared target (which it cannot fold, degrading the whole function to a state
     * machine). A ends jcc, falls to B; B ends jcc, has NO real statements (its only
     * job is the compare), A is its sole predecessor, and B shares a target with A.
     * The emitted C `||`/`&&` preserves the original short-circuit evaluation; B
     * having no statements means no guarded memory load is hoisted ahead of A. */
    void merge_short_circuit() {
        merged_blocks.clear();
        for (int iter = 0; iter < 4000; ++iter) {
            rebuild_edges();
            bool changed = false;
            for (auto& A : blocks) {
                if (merged_blocks.count(A.id) || A.is_switch) continue;
                if (!A.ends_jcc || A.taken < 0 || A.fall < 0 || !A.cond) continue;
                int bi = A.fall;
                if (bi < 0 || (size_t)bi >= blocks.size() || merged_blocks.count(bi) || bi == (int)A.id) continue;
                Block& B = blocks[bi];
                if (B.is_switch || !B.ends_jcc || B.taken < 0 || B.fall < 0 || !B.cond) continue;
                if (B.pred.size() != 1 || B.pred[0] != (int)A.id) continue;
                if (!block_stmts_empty(bi)) continue;
                ExprP comb; int nt, nf;
                if (B.taken == A.taken && B.fall != A.taken) {        /* both → T on their cond */
                    comb = mkBinary("||", clone(A.cond), clone(B.cond), 4);
                    nt = A.taken; nf = B.fall;
                } else if (B.fall == A.taken && B.taken != A.taken) { /* A→T on cond, B→T on !cond */
                    comb = mkBinary("||", clone(A.cond), negate_expr(clone(B.cond)), 4);
                    nt = A.taken; nf = B.taken;
                } else continue;
                if (nt == bi || nf == bi || nt == (int)A.id || nf == (int)A.id) continue;
                A.cond = fold(comb);
                /* Collapse a duplicated predicate `c || c` -> `c`: the ordered
                 * float-equality idiom `ucomiss; jp L; jne L` yields two edges that
                 * both model the SAME `x == k`, so the merged condition (and its De
                 * Morgan negation `x==k && x==k`) is a redundant self-duplicate.
                 * Side-effect-free predicate only. */
                if (A.cond && (A.cond->op == "||" || A.cond->op == "&&") &&
                    A.cond->a && A.cond->b && exprEqual(A.cond->a, A.cond->b) &&
                    !has_call(A.cond->a))
                    A.cond = A.cond->a;
                A.taken = nt; A.fall = nf;
                merged_blocks.insert(bi);
                changed = true;
                break;
            }
            if (!changed) break;
        }
        rebuild_edges();
    }

    /* C3: a boolean-value DIAMOND `if (c) X = 1; else X = 0;` (a `jmp`-over-`mov`
     * setcc the compiler didn't fold) -> `X = c;` (or `X = !c;`). Both arms must be a
     * single `X = const(0/1)` block with A as sole pred, converging on one join. The
     * assignment moves into A and A falls straight to the join. CFG transform mirroring
     * merge_short_circuit; corpus (behavioral) + compile gate verify. Gated
     * DS_NO_BOOLDIAMOND. */
    void fold_boolean_diamonds() {
        if (std::getenv("DS_NO_BOOLDIAMOND")) return;
        rebuild_edges();
        auto single_bool_assign = [&](int b, std::string& xn, int64_t& cv) -> bool {
            if (b < 0 || (size_t)b >= blocks.size()) return false;
            Block& B = blocks[b];
            if (B.is_switch || B.ends_jcc) return false;
            const Stmt* only = nullptr;
            for (auto& s : B.stmts) { if (s.kind == SK::Comment) continue; if (only) return false; only = &s; }
            if (!only || only->kind != SK::Assign || !only->lhs || only->lhs->kind != EK::Var ||
                !only->rhs || only->rhs->kind != EK::Const) return false;
            cv = only->rhs->cval;
            if (cv != 0 && cv != 1) return false;
            xn = only->lhs->name; return true;
        };
        auto usucc = [&](int b) -> int {   /* unconditional successor of a straight block */
            Block& B = blocks[b];
            if (B.ends_jcc || B.is_switch) return -1;
            return B.ends_jmp ? B.taken : B.fall;
        };
        for (auto& A : blocks) {
            if (A.is_switch || !A.ends_jcc || A.taken < 0 || A.fall < 0 || !A.cond) continue;
            int T = A.taken, F = A.fall;
            if (T == F || (size_t)T >= blocks.size() || (size_t)F >= blocks.size()) continue;
            if (blocks[T].pred.size() != 1 || blocks[T].pred[0] != A.id) continue;
            if (blocks[F].pred.size() != 1 || blocks[F].pred[0] != A.id) continue;
            std::string xt, xf; int64_t ct, cf;
            if (!single_bool_assign(T, xt, ct) || !single_bool_assign(F, xf, cf)) continue;
            if (xt != xf || ct == cf) continue;                 /* same var, complementary 0/1 */
            int jt = usucc(T), jf = usucc(F);
            if (jt < 0 || jt != jf || jt == A.id || jt == T || jt == F) continue;
            ExprP val = (ct == 1) ? clone(A.cond) : negate_expr(clone(A.cond));
            Stmt s; s.kind = SK::Assign;
            int w = var_width.count(xt) ? var_width[xt] : 4;
            s.lhs = mkVar(xt, w); s.rhs = val;
            A.stmts.push_back(std::move(s));
            A.ends_jcc = false; A.cond = nullptr; A.ends_jmp = false;
            A.taken = -1; A.fall = jt;                           /* straight fall to the join */
            merged_blocks.insert(T); merged_blocks.insert(F);
        }
        rebuild_edges();
    }

    std::string ind() { return std::string(indent_lvl * 4, ' '); }
    /* true if `s` contains only whitespace (no actual statements/labels) */
    static bool is_blank(const std::string& s) {
        for (char ch : s) if (!isspace((unsigned char)ch)) return false;
        return true;
    }
    /* Remove one indentation level (up to 4 leading spaces) from every line of a
     * previously-rendered block. Used to de-nest a guard's sibling arm without
     * re-running the structurer (which would mark blocks as already-emitted and
     * degrade to gotos). Blank lines are left untouched. */
    static std::string dedent_one(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        size_t i = 0, n = s.size();
        while (i < n) {
            size_t eol = s.find('\n', i);
            if (eol == std::string::npos) eol = n;
            size_t strip = 0;
            while (strip < 4 && i + strip < eol && s[i + strip] == ' ') ++strip;
            out.append(s, i + strip, eol - (i + strip));
            if (eol < n) out.push_back('\n');
            i = eol + 1;
        }
        return out;
    }
    std::string ind(int n) { return std::string(n * 4, ' '); }
    std::string block_label(int id) { return "L_" + hex(blocks[id].addr).substr(2); }

