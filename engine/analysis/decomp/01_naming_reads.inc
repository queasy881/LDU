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

    static long budget_scale() {
        static const long v = [] {
            const char* s = std::getenv("DS_WORK_BUDGET");
            return s ? std::atol(s) : 2000L;   /* work units per instruction */
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
    static long budget_wall_default() {
        static const long v = [] {
            const char* s = std::getenv("DS_WALL_MS");
            return s ? std::atol(s) : 8000L;
        }();
        return v;
    }

    /* Called once the instruction/block lists exist, so the cap can scale. */
    void budget_init() {
        long n = (long)insns.size() + 1;
        long b = (long)blocks.size() + 1;
        budget_cap = 100000L + budget_scale() * n + 4000L * b;
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
        if (!terminated || (int)raw.size() < MINLEN) return false;
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
            if (w == 0) { if ((int)s.size() < MINLEN) return false; out.swap(s); return true; }
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
