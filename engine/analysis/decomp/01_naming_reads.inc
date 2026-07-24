/* 01_naming_reads.inc -- display names, rva->name, bounds-checked image reads
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    ds_engine* e;
    const ds_func* f;
    csh handle = 0;
    bool handle_ok = false;
    const std::map<uint64_t, FuncSig>* sigtab = nullptr;

    std::vector<Insn> insns;
    std::map<uint64_t, int> idx_by_addr;
    std::vector<Block> blocks;
    std::map<uint64_t, int> block_by_addr;

    int  num_params = 0;
    bool param_used[4] = {false, false, false, false};
    std::map<int64_t, std::string> stack_slot_name;   /* norm offset -> vN */
    std::map<int64_t, std::string> param_home_off;    /* norm offset -> aN */
    std::map<int64_t, std::string> slot_init_param;   /* norm -> aN: loop-carried homed param, decl `vN = aN` */
    std::set<uint64_t> home_store_addrs;              /* prologue arg-homing stores */
    std::set<uint64_t> callee_save_addrs;             /* callee-saved save/restore stores */
    std::set<uint64_t> chkstk_call_addrs;             /* prologue __chkstk stack-probe calls */
    std::map<std::string, int>  var_width;
    std::map<std::string, bool> var_unsigned;
    std::map<std::string, bool> var_pointer;
    std::map<std::string, bool> var_is_ll;            /* prefer long long */
    std::map<std::string, bool> var_is_float;         /* declare as float/double */

    /* semantic display names: canonical v<N>/t<N> -> pretty (result, i/j/k). A pure
     * DISPLAY alias — the type maps + Expr::name stay keyed on the canonical name, so
     * this is a zero-semantics rename applied only at the two textual leaves (a Var
     * use in render(), and the identifier in each decl). Gated by DS_NO_AUTONAME. */
    std::map<std::string, std::string> autoname;
    std::string disp(const std::string& n) const {
        auto it = autoname.find(n); return it == autoname.end() ? n : it->second;
    }

    /* User-declared types for this function's variables (ds_engine_set_var_type),
     * keyed by the DISPLAY name the user saw. Unlike `autoname` this is NOT a
     * display alias — decl_type returns it ahead of every inference, so it changes
     * what the output means. Empty for the overwhelming majority of functions, and
     * decl_type early-outs on that. */
    std::map<std::string, std::string> var_user_type;
    /* User-defined struct layouts (ds_engine_define_struct), tag -> member list as
     * C text, plus the offset->name map derived from it. */
    std::map<std::string, std::string> user_struct_body;
    std::map<std::string, std::map<int64_t, std::string>> user_struct_fields;

    /* Parse a member list ("int health; float x; char* name;") into offsets using
     * the platform's natural alignment, so a field at a known offset can be named.
     *
     * Deliberately handles only what a person actually types into a struct
     * dialogue: the base scalar types, a pointer, and a `[N]` array. Anything it
     * does not recognise ENDS the parse rather than guessing a size — every later
     * offset would be wrong, and a wrong field name on a real access is exactly
     * the confident lie the house rules forbid. */
    static std::map<int64_t, std::string> parse_struct_body(const std::string& body) {
        std::map<int64_t, std::string> out;
        int64_t off = 0;
        size_t i = 0;
        while (i < body.size()) {
            while (i < body.size() && (isspace((unsigned char)body[i]) || body[i] == ';')) ++i;
            if (i >= body.size()) break;
            size_t end = body.find(';', i);
            std::string decl = body.substr(i, end == std::string::npos ? std::string::npos : end - i);
            i = (end == std::string::npos) ? body.size() : end + 1;
            /* split into type words + the declarator */
            std::vector<std::string> tok;
            std::string cur;
            for (char c : decl) {
                if (isspace((unsigned char)c)) { if (!cur.empty()) { tok.push_back(cur); cur.clear(); } }
                else if (c == '*') { if (!cur.empty()) { tok.push_back(cur); cur.clear(); } tok.push_back("*"); }
                else cur += c;
            }
            if (!cur.empty()) tok.push_back(cur);
            if (tok.size() < 2) break;
            std::string name = tok.back(); tok.pop_back();
            int64_t count = 1;
            size_t br = name.find('[');
            if (br != std::string::npos) {
                count = std::strtoll(name.c_str() + br + 1, nullptr, 0);
                if (count <= 0) count = 1;
                name = name.substr(0, br);
            }
            bool is_ptr = false;
            std::string ty;
            for (auto& t : tok) { if (t == "*") is_ptr = true; else { if (!ty.empty()) ty += " "; ty += t; } }
            int64_t sz;
            if (is_ptr) sz = 8;
            else if (ty == "char" || ty == "signed char" || ty == "unsigned char" ||
                     ty == "int8_t" || ty == "uint8_t" || ty == "bool") sz = 1;
            else if (ty == "short" || ty == "unsigned short" || ty == "int16_t" || ty == "uint16_t") sz = 2;
            else if (ty == "int" || ty == "unsigned" || ty == "unsigned int" ||
                     ty == "int32_t" || ty == "uint32_t" || ty == "float" || ty == "long") sz = 4;
            else if (ty == "long long" || ty == "unsigned long long" || ty == "int64_t" ||
                     ty == "uint64_t" || ty == "double" || ty == "size_t") sz = 8;
            else break;                       /* unknown type -> stop, do not guess */
            if (name.empty()) break;
            int64_t align = sz > 8 ? 8 : sz;
            if (align > 1 && off % align) off += align - (off % align);
            out[off] = name;
            off += sz * count;
        }
        return out;
    }

    void load_user_structs() {
        user_struct_body.clear();
        user_struct_fields.clear();
        if (!e) return;
        size_t n = ds_engine_get_structs(e, nullptr, 0);
        if (!n) return;
        std::vector<ds_user_struct> tmp(n);
        n = ds_engine_get_structs(e, tmp.data(), tmp.size());
        for (size_t i = 0; i < n; ++i) {
            if (!tmp[i].name[0] || !tmp[i].body[0]) continue;
            user_struct_body[tmp[i].name] = tmp[i].body;
            user_struct_fields[tmp[i].name] = parse_struct_body(tmp[i].body);
        }
    }

    /* The user struct tag a variable was typed with, or "" — `struct Player*` -> Player. */
    std::string user_struct_tag_of(const std::string& var) const {
        auto it = var_user_type.find(var);
        if (it == var_user_type.end()) {
            auto ai = autoname.find(var);
            if (ai == autoname.end()) return "";
            it = var_user_type.find(ai->second);
            if (it == var_user_type.end()) return "";
        }
        std::string t = it->second;
        size_t p = t.find("struct ");
        if (p == std::string::npos) return "";
        t = t.substr(p + 7);
        while (!t.empty() && (t.back() == '*' || isspace((unsigned char)t.back()))) t.pop_back();
        return user_struct_body.count(t) ? t : "";
    }

    /* Load the overrides recorded for THIS function. Annotations bind by content
     * hash (see annotations.cpp), and ds_anno_resolve has already published the
     * answer in `bound`, so this just reads it. */
    void load_user_types() {
        var_user_type.clear();
        if (!e || !f) return;
        /* COPY under the annotation lock: a concurrent ds_engine_set_var_type may
         * reallocate the store while this decompile is reading it, and bridge's
         * `unsafe impl Sync for Engine` lets N threads decompile at once. */
        size_t n = ds_engine_get_var_types(e, f->rva, nullptr, 0);
        if (!n) return;
        std::vector<ds_var_type> tmp(n);
        n = ds_engine_get_var_types(e, f->rva, tmp.data(), tmp.size());
        for (size_t i = 0; i < n; ++i) var_user_type[tmp[i].var] = tmp[i].type;
    }

    bool used_return = false;
    int  ret_width = 4;
    bool ret_byte_return = false;   /* return is a byte (bool/char) — mask to al */

    std::map<std::string,int> extern_callees;         /* name -> ret_kind (0/1/2) */
    /* Opaque "__"+mnem intrinsics minted for UNMODELED ops -> emit count. Recorded
     * at the single mnemonic-concat site, never by scanning text: most __-prefixed
     * intrinsics in the output (__readgsqword/__umulh/__min/...) are EXACTLY modeled
     * and have real construction sites, so a text scan would brand them unmodeled. */
    std::map<std::string,int> opaque_ops;
    int  temp_seq = 0;
    std::map<int, std::string> temp_name;             /* (blk<<5|reg) -> tN unused */

    /* whole-program PE tables (reloc pointer slots + .pdata), parsed once/engine */
    std::shared_ptr<const PeTables> petab;

    /* Env flags the SHELL toggles at runtime (session.rs sets DS_LINE_ADDR around
     * the eager pass; ipc.rs sets it per interactive call), so they cannot be
     * cached in a process-lifetime static like the DS_NO_ / DS_DBG_ switches.
     * They ARE stable for the duration of one ds_decompile call, so read them
     * once per instance — emit_stmts otherwise called getenv() for every single
     * statement it printed, on the hottest path in the emitter. */
    bool opt_line_addr = false;

    /* ================= THE WORK BUDGET (never-freeze guarantee) =================
     *
     * Decompiling is a pile of analyses whose cost depends on CFG SHAPE, not size:
     * a dataflow fixpoint re-runs until it stops changing, the structurer explores
     * alternative shapes and rolls back, duplication trials nest. Each is bounded
     * "in practice" and unbounded in theory, so on an adversarial or merely unusual
     * CFG any one of them can run for minutes. Capping them one at a time as they
     * are discovered does not generalize: the next binary has a different worst
     * case. So the guarantee is structural instead:
     *
     *   Every expensive loop spends from ONE budget. When it is gone, the
     *   decompiler stops IMPROVING the output and finishes with what it has.
     *
     * That is safe because every pass past the lift is OPTIONAL — it makes the
     * output nicer, never more correct. The required path (disassemble -> CFG ->
     * lift -> emit) is linear in function size. So the ladder is:
     *
     *   budget available   full pipeline: all analyses, structured emission
     *   budget spent       optional passes skipped; structured emission still tried
     *   budget spent in    emission abandoned -> emit_goto_cfg(), the complete
     *     the emitter      labeled goto form, one render per block, linear
     *
     * Each rung is correct and complete; they differ only in prettiness. Nothing
     * is ever truncated and no code is ever dropped.
     *
     * The cap SCALES WITH THE FUNCTION so the rule is size-fair rather than a
     * magic constant tuned to one binary: a function may spend a large multiple of
     * its own linear size, which is far more than any well-behaved CFG needs and
     * still a hard ceiling for a pathological one.
     *
     * Determinism: the meter counts WORK, not time, so a function decompiles
     * identically whether it runs alone or on 16 threads (the throughput test
     * asserts exactly this). The wall-clock deadline below is a separate last
     * resort for a loop nobody instrumented; it is set high enough that reaching
     * it means something is genuinely wrong, and it is what makes the promise
     * "never freezes" hold even for code paths this budget does not yet cover.
     *
     * DS_WORK_BUDGET / DS_WALL_MS override; 0 disables that limb. */
    long  budget_spent = 0;
    long  budget_cap   = 0;
    bool  budget_tripped = false;
    long  budget_wall_ms = 0;
    long  budget_calls = 0;
    std::chrono::steady_clock::time_point budget_t0;

    /* DS_WORK_BUDGET, when set, is an ABSOLUTE unit cap (not a per-instruction
     * scale); 0 means "use the size-derived default in budget_init". */
    static long budget_scale() {
        static const long v = [] {
            const char* s = std::getenv("DS_WORK_BUDGET");
            return s ? std::atol(s) : 0L;
        }();
        return v;
    }
    /* Absolute per-function ceiling — a SAFETY NET, not a performance knob.
     *
     * Tripping it costs output quality: the emitter falls back to the labeled
     * goto-CFG, so that function's goto count jumps. Tuning this DOWN to buy
     * speed is therefore the wrong trade — measured at 600ms it turned 10 of 600
     * ntdll functions into goto soup and pushed the total from 2657 to 4054.
     * Speed has to come from doing less redundant work (see the trial memo),
     * not from giving up earlier.
     *
     * So it is set well above any function that is merely slow, and exists only
     * so that a genuinely pathological CFG — or a loop nobody has profiled yet —
     * cannot hang the app. At this value it fires on essentially nothing, and
     * output is identical to having no deadline at all. */
    /* WALL CLOCK OFF BY DEFAULT.
     *
     * A timing-based limit makes the OUTPUT depend on machine load: the same
     * function decompiled alone finishes under the deadline and decompiled on 16
     * busy threads does not, so it structures one way serially and another way in
     * parallel. That is exactly what the throughput test asserts against, and it
     * duly failed on kernel32 fun_000066c0 (~3.4s serial) once the label-repair
     * work pushed it nearer the limit.
     *
     * The work meter below bounds the same thing deterministically, so the clock
     * is not needed and its only effect was to make results irreproducible. Set
     * DS_WALL_MS to re-enable it as a belt-and-braces stop. */
    static long budget_wall_default() {
        static const long v = [] {
            const char* s = std::getenv("DS_WALL_MS");
            return s ? std::atol(s) : 0L;
        }();
        return v;
    }

    /* Called once the instruction/block lists exist, so the cap can scale.
     *
     * This is now the ONLY per-function limit (the wall clock is off by default),
     * so it has to actually bind rather than sit far above anything reachable —
     * it previously scaled to millions of units and never fired, leaving the
     * timing-dependent clock doing all the work. Units are charged at roughly
     * 7.5k/second of emitter time, so this bounds a pathological function to a
     * few seconds while sitting well above every well-behaved one (the largest
     * healthy kernel32 function measured ~25k). Deterministic: identical alone or
     * on 16 threads. DS_WORK_BUDGET overrides. */
    void budget_init() {
        long n = (long)insns.size() + 1;
        long b = (long)blocks.size() + 1;
        budget_cap = budget_scale() > 0 ? budget_scale()
                                        : (60000L + 8L * n + 40L * b);
        /* SPEND THE METER WHERE IT CAN BUY STRUCTURE.
         *
         * A REDUCIBLE CFG has a goto-free structured form; every goto it emits is
         * a structurer limitation, and more work converts directly into recovered
         * loops and ifs. An IRREDUCIBLE one provably does not (without node
         * splitting or a dispatch variable), so its gotos are unavoidable and
         * extra budget buys nothing but time.
         *
         * Measured on disasmstudio.exe: the worst offenders overran the base cap
         * by UNDER 1% and lost their whole structure for it; the reducible ones
         * needed ~10x to finish (fun_0003b2f0: 260 gotos -> 40 at 800k). Raising
         * the cap for everything cost 2.7x wall time and bought nothing on the
         * irreducible half, which is where the biggest functions are. Gating on
         * reducibility puts the time exactly where it pays.
         *
         * cfg_is_reducible is O(V*(V+E)) and runs once per function.
         * DS_WORK_BUDGET (explicit) still wins outright. */
        if (budget_scale() <= 0 && !std::getenv("DS_NO_REDBUDGET") && cfg_is_reducible())
            budget_cap *= 24L;
        budget_spent = 0;
        budget_tripped = false;
        budget_wall_ms = budget_wall_default();
        budget_t0 = std::chrono::steady_clock::now();
    }

    /* Spend `n` units. Returns false once the budget is gone. Cheap: the clock is
     * consulted only every 4096th call so the deadline costs nothing in the hot
     * loops it protects. */
    bool budget_spend(long n) {
        static const bool dbg = std::getenv("DS_DBG_BUDGET") != nullptr;
        ++budget_calls;
        if (dbg && (budget_calls % 25) == 0) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - budget_t0).count();
            fprintf(stderr, "[budget] calls=%ld spent=%ld wall=%ld elapsed=%lldms tripped=%d\n",
                    budget_calls, budget_spent, budget_wall_ms, (long long)ms, (int)budget_tripped);
        }
        if (budget_tripped) return false;
        budget_spent += n;
        if (budget_cap > 0 && budget_spent >= budget_cap) { budget_tripped = true; return false; }
        if (budget_wall_ms > 0 && (budget_spent & 0xFFF) < n) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - budget_t0).count();
            if (ms >= budget_wall_ms) { budget_tripped = true; return false; }
        }
        return true;
    }
    bool budget_ok() const { return !budget_tripped; }

    Decompiler(ds_engine* eng, const ds_func* fn,
               const std::map<uint64_t, FuncSig>* st)
        : e(eng), f(fn), sigtab(st) {
        petab = get_pe_tables(eng);
        opt_line_addr = std::getenv("DS_LINE_ADDR") != nullptr;
    }
    ~Decompiler() { if (handle_ok) cs_close(&handle); }

    /* ---- image reads (bounds-checked) ---- */
    /* Name seeded for a DATA address (ds_engine_scan_class_globals seeds the
     * class-typed globals here), or "" if none. Lives in this section because
     * render_const's parameter is itself called `e` and shadows the engine. */
    std::string data_symbol_name(uint64_t rva) const {
        if (!e) return "";
        for (size_t i = 0; i < e->symbol_len; ++i)
            if (e->symbols[i].rva == rva && e->symbols[i].name[0])
                return std::string(e->symbols[i].name);
        return "";
    }

    bool read_u8(uint64_t rva, uint8_t& out) {
        if (!e || !e->image || rva >= e->image_size) return false;
        out = e->image[rva]; return true;
    }
    bool read_i32(uint64_t rva, int32_t& out) {
        if (!e || !e->image) return false;
        if (rva + 4 > e->image_size) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= (uint32_t)e->image[rva + i] << (8 * i);
        out = (int32_t)v; return true;
    }
    bool read_i64(uint64_t rva, int64_t& out) {
        if (!e || !e->image) return false;
        if (rva + 8 > e->image_size) return false;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)e->image[rva + i] << (8 * i);
        out = (int64_t)v; return true;
    }
    /* C-escape one byte onto `s`; false if it is not printable, i.e. the run is not a
     * string. Shared by read_cstring (.rdata literals) and recover_stack_strings so both
     * accept exactly the same byte set. */
    static bool cstr_escape_byte(uint8_t b, std::string& s, bool allow_high = false) {
        if (b == '\n') { s += "\\n"; return true; }
        if (b == '\t') { s += "\\t"; return true; }
        if (b == '\r') { s += "\\r"; return true; }
        if (b == '"')  { s += "\\\""; return true; }
        if (b == '\\') { s += "\\\\"; return true; }
        if (b < 0x20) return false;                /* a control byte -> binary data, not a string */
        if (b >= 0x7f) {
            /* A HIGH BYTE is UTF-8, not garbage. Rejecting the whole run on the first one threw
             * away every log string the program actually prints:
             *     [NullWare] \342\234\223 All hooks installed!\n     ("✓")
             *     [NullWare] \342\234\227 Hook initialization failed!\n ("✗")
             *     \342\225\221         NullWare Internal            \342\225\221  (box drawing)
             * -- 4 of the 19 raw addresses still passed where a string belongs.
             *
             * OCTAL, not \xNN: a hex escape has NO length limit in C, so "\x41" followed by a
             * literal 'B' parses as ONE escape \x41B. Octal is capped at 3 digits and cannot
             * swallow the next character.
             * Only for callers that pass allow_high AND enforce a printable-majority ratio --
             * on its own this would happily read a binary table as a "string". */
            if (!allow_high) return false;
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\%03o", (unsigned)b);
            s += buf; return true;
        }
        s += (char)b; return true;
    }
    /* Minimum length for rendering an operand as a string LITERAL.
     *
     * This is deliberately lower than the blind data-scan threshold, because the
     * evidence is different in kind. The scanner is guessing from bytes alone; by
     * the time we get here the value is already known to be used as a POINTER,
     * and the target is verified read-only, NUL-terminated and printable. Under
     * those constraints a 2-character hit is overwhelmingly a real literal.
     *
     * At 4 the most common format strings in existence — "%d", "%s", "%c", "%x" —
     * all fell below the bar, so `scanf("%d", &a)` rendered as
     * `fun_0000b5c0(0x3a654, s1)`: the call was right but its most informative
     * operand was printed as a bare address. Two is the shortest length that
     * still requires a NUL terminator to agree with it. */
    static const int CSTR_MINLEN = 2;
    /* If `rva` addresses a READ-ONLY, null-terminated, printable C string of at least
     * MINLEN chars, return it C-escaped (no quotes). Recovers string-literal operands
     * the compiler passed by address — Ghidra-style .rdata string recovery. */
    /* Is `p[0..n)` a WELL-FORMED UTF-8 sequence? This is the discriminator that lets high
     * bytes into a string safely. A printable-majority RATIO was tried first and is wrong: it
     * rejects `════════ NullWare ════════`, a real separator line that is almost entirely
     * box-drawing characters. Valid UTF-8 is a far stronger signal than any ratio -- random
     * binary violates it within a byte or two (a stray 0x80-0xBF with no lead, a truncated
     * sequence, an over-long form), while genuine text never does.
     * Rejects the over-long encodings and the surrogate range too, so a crafted blob cannot
     * masquerade as text. */
    static bool valid_utf8(const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ) {
            uint8_t b = p[i];
            if (b < 0x80) { ++i; continue; }
            int need; uint32_t cp;
            if ((b & 0xE0) == 0xC0)      { need = 1; cp = b & 0x1F; }
            else if ((b & 0xF0) == 0xE0) { need = 2; cp = b & 0x0F; }
            else if ((b & 0xF8) == 0xF0) { need = 3; cp = b & 0x07; }
            else return false;                       /* a bare continuation byte, or 0xF8+ */
            if (i + (size_t)need >= n) return false;  /* the continuation bytes run past the end */
            for (int k = 1; k <= need; ++k) {
                uint8_t c = p[i + k];
                if ((c & 0xC0) != 0x80) return false;    /* not a continuation */
                cp = (cp << 6) | (c & 0x3F);
            }
            if (need == 1 && cp < 0x80)    return false;         /* over-long */
            if (need == 2 && cp < 0x800)   return false;         /* over-long */
            if (need == 3 && cp < 0x10000) return false;         /* over-long */
            if (cp > 0x10FFFF)             return false;         /* out of range */
            if (cp >= 0xD800 && cp <= 0xDFFF) return false;      /* a lone surrogate */
            i += (size_t)need + 1;
        }
        return true;
    }
    /* Is `rva` a position INSIDE the .rdata string pool — i.e. do the bytes right
     * before it terminate a genuine literal of the same width?
     *
     * This exists so the EMPTY string can be recovered. `""` / `L""` is a real,
     * extremely common literal (the canonical "no value" default: `AslPathCombine(
     * dst, arg ? arg : L"", ...)`), but it is a lone NUL, so every length-based
     * filter rejects it — and a NUL is also what every other kind of binary data is
     * full of, which is exactly why the filter has to exist. Length alone cannot
     * tell the two apart, so use POSITION instead: an address is the empty string
     * only if it sits immediately after the terminator of a well-formed literal, so
     * it is provably in a run of string data. A NUL inside a pointer table or a
     * relocation array has binary bytes before it and is rejected.
     *
     * Without this, kernel32 rendered `L""` as the bare integer 0x904cc in 17
     * functions — including `*a3 = 0x904cc;` and `wcslen(a3 ? a3 : 0x904cc)`, where
     * the SAME address is obviously a wide string from its use — and `""` as
     * 0x91085 in 5 more. The same constant printing as a literal in one function
     * and a magic number in the next is precisely the ambiguity to avoid. */
    bool in_string_pool(uint64_t rva, bool wide) {
        const int step = wide ? 2 : 1;
        const int MAXBACK = 512;
        auto unit = [&](uint64_t at, uint32_t& w) -> bool {
            uint8_t lo, hi = 0;
            if (!read_u8(at, lo)) return false;
            if (wide && !read_u8(at + 1, hi)) return false;
            w = (uint32_t)lo | ((uint32_t)hi << 8);
            return true;
        };
        if (rva < (uint64_t)step) return false;
        uint32_t w;
        /* the unit immediately before must be a terminator */
        if (!unit(rva - step, w) || w != 0) return false;
        /* walk further back over the literal it terminates; it must be printable
         * and at least CSTR_MINLEN long before its own terminator (or the start of
         * the readable region) is reached. */
        int n = 0;
        for (uint64_t at = rva - 2 * (uint64_t)step;
             n < MAXBACK && at + step > at; at -= (uint64_t)step) {
            if (!in_data_rva(at) || !unit(at, w)) break;
            if (w == 0) break;                       /* found the literal's start */
            if (w < 0x20 || w > 0x7e) return false;  /* binary before us -> not a pool */
            ++n;
            if (at < (uint64_t)step) break;
        }
        return n >= CSTR_MINLEN;
    }

    bool read_cstring(uint64_t rva, std::string& out) {
        if (!in_data_rva(rva) || addr_writable(rva)) return false;   /* read-only data only */
        const int MINLEN = CSTR_MINLEN, MAXLEN = 4096;
        /* Read the raw run first: the UTF-8 check needs to look AHEAD at continuation bytes,
         * which a byte-at-a-time escape loop cannot do. */
        std::vector<uint8_t> raw;
        bool terminated = false;
        for (int i = 0; i < MAXLEN; ++i) {
            uint8_t b;
            if (!read_u8(rva + (uint64_t)i, b)) return false;
            if (b == 0) { terminated = true; break; }
            if (b < 0x20 && b != '\n' && b != '\t' && b != '\r') return false;  /* control -> data */
            raw.push_back(b);
        }
        if (!terminated) return false;
        if (raw.empty()) { if (!in_string_pool(rva, false)) return false; out.clear(); return true; }
        if ((int)raw.size() < MINLEN) return false;
        bool any_high = false;
        for (uint8_t b : raw) if (b >= 0x7f) { any_high = true; break; }
        if (any_high && !valid_utf8(raw.data(), raw.size())) return false;
        std::string s;
        for (uint8_t b : raw)
            if (!cstr_escape_byte(b, s, /*allow_high=*/true)) return false;
        out.swap(s);
        return true;
    }
    /* A Rust `&str`: an EXPLICIT (pointer, length) pair, NOT NUL-terminated.
     *
     * rustc packs literals into .rdata back-to-back with no terminators, so one
     * 25-byte run backs `"\n"`, `"}"`, `"["`, `"{"`, `","`, `": "`, `"]"`, `"\""`,
     * `"false"`, `"true"` and `"null"` — every one of them an offset plus a length
     * into that single run. read_cstring's read-to-the-next-NUL then runs off the
     * end of the intended literal and into its neighbours, so a 4-byte `"true"`
     * printed as `"truenull,:"` — a confident, WRONG answer.
     *
     * Here the length is authoritative and no terminator is required. Deliberately
     * has no MINLEN: the 1-byte literals (`","`, `"{"`) are exactly the ones the
     * NUL rule mangles worst. Everything else matches read_cstring's filters — the
     * whole run must be read-only, mapped, control-free and valid UTF-8 — plus an
     * interior NUL REJECTS the run, since a NUL inside a claimed str means the
     * pair was never a str to begin with.
     *
     * Callers must gate on is_rust_image(); see the note there for why the rule
     * cannot be applied to C. */
    bool read_rust_str(uint64_t rva, uint64_t len, std::string& out) {
        const uint64_t MAXLEN = 4096;
        if (len == 0 || len > MAXLEN) return false;
        if (rva + len < rva) return false;                            /* wrap */
        /* first AND last byte read-only + mapped; read_u8 covers the interior */
        if (!in_data_rva(rva) || addr_writable(rva)) return false;
        if (!in_data_rva(rva + len - 1) || addr_writable(rva + len - 1)) return false;
        std::vector<uint8_t> raw;
        raw.reserve((size_t)len);
        for (uint64_t i = 0; i < len; ++i) {
            uint8_t b;
            if (!read_u8(rva + i, b)) return false;
            if (b == 0) return false;                                 /* not a str slice */
            if (b < 0x20 && b != '\n' && b != '\t' && b != '\r') return false;
            raw.push_back(b);
        }
        bool any_high = false;
        for (uint8_t b : raw) if (b >= 0x7f) { any_high = true; break; }
        if (any_high && !valid_utf8(raw.data(), raw.size())) return false;
        std::string s;
        for (uint8_t b : raw)
            if (!cstr_escape_byte(b, s, /*allow_high=*/true)) return false;
        out.swap(s);
        return true;
    }

    /* The UTF-16 twin of read_cstring. A wide literal is invisible to read_cstring by
     * construction: `L"VALORANT-Win64-Shipping.exe"` is the bytes 56 00 41 00 4c 00 ..., so a
     * byte-wise reader sees 'V' then a NUL and gives up -- which is why every LPCWSTR argument
     * in the output was a bare address:
     *     GetModuleHandleW(0x87718)
     *     GetModuleHandleW(L"VALORANT-Win64-Shipping.exe")
     * Returns the text C-escaped and WITHOUT the quotes or the L prefix; the caller adds them.
     *
     * Deliberately conservative: BMP-range, printable, even-length, read-only data only. A
     * non-ASCII code point has no safe single-byte escape here, so anything outside 0x20..0x7e
     * REJECTS the whole run rather than guessing a transliteration -- an address is a less
     * wrong answer than a mangled string. */
    bool read_wstring(uint64_t rva, std::string& out) {
        if (!in_data_rva(rva) || addr_writable(rva)) return false;   /* read-only data only */
        if (rva & 1) return false;                                   /* wide literals are aligned */
        const int MINLEN = CSTR_MINLEN, MAXLEN = 2048;
        std::string s;
        for (int i = 0; i < MAXLEN; ++i) {
            uint8_t lo, hi;                              /* UTF-16LE, built from read_u8: the
                                                          * class has no 16-bit reader and one
                                                          * is not worth inventing for this */
            if (!read_u8(rva + (uint64_t)i * 2, lo)) return false;
            if (!read_u8(rva + (uint64_t)i * 2 + 1, hi)) return false;
            uint16_t w = (uint16_t)lo | ((uint16_t)hi << 8);
            if (w == 0) {
                if (s.empty()) return in_string_pool(rva, true) ? (out.clear(), true) : false;
                if ((int)s.size() < MINLEN) return false;
                out.swap(s); return true;
            }
            if (w > 0x7f) return false;                  /* not representable as a plain escape */
            if (!cstr_escape_byte((uint8_t)w, s)) return false;
        }
        return false;   /* unterminated within MAXLEN */
    }
    /* Is `rva` inside a readable, NON-executable segment (.rdata/.data)? Used to
     * recognize a static-array access whose module-base register was lost. */
    bool in_data_rva(uint64_t rva) {
        if (!e) return false;
        for (size_t i = 0; i < e->segment_len; ++i) {
            const ds_segment& s = e->segments[i];
            if (rva >= s.rva && rva < s.rva + s.size)
                return (s.flags & DS_FLAG_X) == 0;   /* data, not code */
        }
        return false;
    }

    /* Is `rva` the exact start of a recovered function? (function-pointer lea) */
    bool is_func_start(uint64_t rva) {
        if (!e) return false;
        for (size_t i = 0; i < e->func_len; ++i)
            if (e->funcs[i].rva == rva) return true;
        return false;
    }

    /* Is `rva` in a WRITABLE segment (.data/.bss)? Such a location is a mutable
     * global — its image bytes are only the INITIAL value, so a load must be a
     * variable reference, not an inlined constant. */
    bool addr_writable(uint64_t rva) {
        if (!e) return false;
        for (size_t i = 0; i < e->segment_len; ++i) {
            const ds_segment& s = e->segments[i];
            if (rva >= s.rva && rva < s.rva + s.size)
                return (s.flags & DS_FLAG_W) != 0;
        }
        return false;
    }

    /* ---- name resolution for a call/jmp target rva ---- */
    std::string name_for_rva(uint64_t rva) {
        if (!e) return "sub_" + hex(rva).substr(2);
        for (size_t i = 0; i < e->func_len; ++i)
            if (e->funcs[i].rva == rva && e->funcs[i].name[0])
                return sani(e->funcs[i].name);
        for (size_t i = 0; i < e->symbol_len; ++i)
            if (e->symbols[i].rva == rva && e->symbols[i].name[0])
                return sani(e->symbols[i].name);
        for (size_t i = 0; i < e->func_len; ++i)
            if (e->funcs[i].rva == rva)
                return "sub_" + hex(rva).substr(2);
        for (size_t i = 0; i < e->import_len; ++i)
            if (e->imports[i].iat_rva == rva && e->imports[i].name[0])
                return sani(e->imports[i].name);
        return "sub_" + hex(rva).substr(2);
    }

    /* CLASS RECONSTRUCTION: if `addr` (an RVA or VA) is a recovered RTTI vtable — the scanner
     * seeds `<Class>__vftable` (RTTI kind class) or `<Class>__vfstruct` (kind struct) at the
     * vtable rva — return the class name and, via `*is_struct`, the RTTI KIND so the type emits
     * with the correct `class`/`struct` keyword (Hex-Rays "class" reconstruction). */
