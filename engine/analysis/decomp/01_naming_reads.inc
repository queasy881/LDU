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

    Decompiler(ds_engine* eng, const ds_func* fn,
               const std::map<uint64_t, FuncSig>* st)
        : e(eng), f(fn), sigtab(st) { petab = get_pe_tables(eng); }
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
    static bool cstr_escape_byte(uint8_t b, std::string& s) {
        if (b == '\n') { s += "\\n"; return true; }
        if (b == '\t') { s += "\\t"; return true; }
        if (b == '\r') { s += "\\r"; return true; }
        if (b == '"')  { s += "\\\""; return true; }
        if (b == '\\') { s += "\\\\"; return true; }
        if (b < 0x20 || b >= 0x7f) return false;   /* non-printable byte -> not a string */
        s += (char)b; return true;
    }
    static const int CSTR_MINLEN = 4;
    /* If `rva` addresses a READ-ONLY, null-terminated, printable C string of at least
     * MINLEN chars, return it C-escaped (no quotes). Recovers string-literal operands
     * the compiler passed by address — Ghidra-style .rdata string recovery. */
    bool read_cstring(uint64_t rva, std::string& out) {
        if (!in_data_rva(rva) || addr_writable(rva)) return false;   /* read-only data only */
        const int MINLEN = CSTR_MINLEN, MAXLEN = 4096;
        std::string s;
        for (int i = 0; i < MAXLEN; ++i) {
            uint8_t b;
            if (!read_u8(rva + (uint64_t)i, b)) return false;
            if (b == 0) { if ((int)s.size() < MINLEN) return false; out.swap(s); return true; }
            if (!cstr_escape_byte(b, s)) return false;
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
