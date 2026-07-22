/* 09_structs.inc -- struct recovery: fields, nested, array-of-struct, classes
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    struct ParamStruct {
        std::string tag;                     /* e.g. "s_a1" */
        std::map<int64_t,int>  fw;           /* offset -> field width */
        std::map<int64_t,bool> fu, ff, fptr; /* offset -> unsigned / float / pointer */
        std::map<int64_t,std::string> fptr_tag; /* offset -> nested struct tag (field is `struct T*`) */
        int64_t stride = 0;                  /* >0: array-element struct, padded to this size */
        bool is_class = false;               /* tag is an RTTI class name -> guard the typedef */
        bool shared_typedef = false;         /* tag is a shared NAMED type (Vec2/3/4) -> include-guard it */
        bool cls_kw_struct = false;          /* RTTI kind is `struct` (U/T tag) rather than `class` (V) */
        std::string qual_name;               /* RAW qualified RTTI name (game::Entity) for the namespace block */
        bool is_vector = false;              /* MSVC std::vector {_Myfirst,_Mylast,_Myend} range struct */
        bool is_stdstring = false;           /* MSVC std::string {_Bx,_Mysize,_Myres} SSO struct */
        /* offset -> {C type, byte size} for a field an API contract names exactly, e.g. a
         * CRITICAL_SECTION field whose address is passed to InitializeCriticalSection. Rendered
         * as that type with `size` bytes reserved; the code never touches its internals (the
         * API does), so it does not overlap a recovered field. */
        std::map<int64_t,std::pair<std::string,int>> ftype;
    };
    std::map<std::string, ParamStruct> param_structs;   /* param name -> layout */
    std::map<std::string, std::set<int64_t>> struct_field_ptr;  /* param -> offsets whose value is used as an address */
    /* a struct field whose LOADED VALUE is used as a memory base address holds a
     * pointer: record it so the field declares `void*` and its uses get (char*). */
    void scan_field_ptr(const ExprP& e) {
        if (!e) return;
        auto note = [&](ExprP o) {
            while (o && o->kind==EK::Cast) o = o->a;
            if (o && o->kind==EK::Mem && o->a && (o->width==8 || o->width==0)) {
                std::string p; int64_t off;
                if (struct_base_offset(o->a, p, off)) struct_field_ptr[p].insert(off);
            }
        };
        if (e->kind == EK::Mem && e->a) {
            /* base of a deref address `*(field + K)` / `*field` */
            ExprP base = e->a;
            while (base && base->kind==EK::Binary && (base->op=="+"||base->op=="-")) base = base->a;
            note(base);
        }
        /* a field-load CAST TO A POINTER (directly or as `(T*)(field + idx)`) is an
         * unambiguous pointer base. NB: only the field-load side is note()'d; an int
         * OFFSET operand is not a Mem-width-8 field-load so it stays integer — so this
         * never turns a genuine `ptr + int` into `ptr + ptr`. */
        if (e->kind == EK::Cast && e->op.find('*') != std::string::npos && e->a) {
            ExprP inner = e->a;
            while (inner && inner->kind==EK::Cast) inner = inner->a;
            if (inner && inner->kind==EK::Binary && (inner->op=="+"||inner->op=="-")) { note(inner->a); note(inner->b); }
            else note(inner);
        }
        scan_field_ptr(e->a); scan_field_ptr(e->b); scan_field_ptr(e->c);
        for (auto& a : e->args) scan_field_ptr(a);
    }
    bool is_struct_ptr_field(const ExprP& mem) {
        if (param_structs.empty() || !mem || mem->kind != EK::Mem || !mem->a) return false;
        std::string p; int64_t off;
        if (!struct_base_offset(mem->a, p, off)) return false;
        auto it = param_structs.find(p);
        if (it == param_structs.end()) return false;
        auto fit = it->second.fptr.find(off);
        return fit != it->second.fptr.end() && fit->second;
    }
    /* True when the Mem lvalue addresses a recovered struct field typed FLOAT/double.
     * Used to reinterpret a raw integer store into it as a bit-preserving `*(float*)`
     * copy (a `mov [float_field], r32` fed by a plain `mov r32,[mem]` GP dword copy). */
    bool is_struct_float_field(const ExprP& mem) {
        if (param_structs.empty() || !mem || mem->kind != EK::Mem || !mem->a) return false;
        std::string p; int64_t off;
        if (!struct_base_offset(mem->a, p, off)) return false;
        auto it = param_structs.find(p);
        if (it == param_structs.end()) return false;
        auto fit = it->second.ff.find(off);
        return fit != it->second.ff.end() && fit->second;
    }
    /* the nested-struct TAG a `struct T*` field points to (top-level OR nested base), for
     * casting a value stored into it. Returns "" if the Mem is not a retyped ptr field. */
    std::string struct_ptr_field_tag(const ExprP& mem) {
        if (param_structs.empty() || !mem || mem->kind != EK::Mem || !mem->a) return "";
        std::string p; int64_t off;
        if (!struct_base_offset(mem->a, p, off) && !nested_base_offset(mem->a, p, off)) return "";
        auto it = param_structs.find(p);
        if (it == param_structs.end()) return "";
        auto t = it->second.fptr_tag.find(off);
        return t != it->second.fptr_tag.end() ? t->second : "";
    }

    bool is_ptr_param_name(const std::string& nm) {
        if (nm.size() < 2 || nm[0] != 'a') return false;
        for (size_t i = 1; i < nm.size(); ++i) if (!isdigit((unsigned char)nm[i])) return false;
        std::string dt = decl_type(nm);
        return !dt.empty() && dt.back() == '*';
    }
    /* A global whose stored VALUE is used as a struct base: `qword_XXXX` = the 8-byte
     * pointer at a read-write .data address, dereferenced with a field offset. Matches
     * the named_globals rendering so `((struct tag*)qword_XXXX)->field_K` reads back the
     * same field. Only width-8 non-float loads of a real data address qualify. */
    bool is_global_base(const ExprP& b, std::string& name) {
        if (std::getenv("DS_NO_GSTRUCT")) return false;
        ExprP x = b; int g = 0;
        while (x && x->kind == EK::Cast && g++ < 8) x = x->a;
        if (x && x->kind == EK::Mem && x->a && x->a->kind == EK::Const &&
            x->width == 8 && !x->is_float &&
            (uint64_t)x->a->cval > 0x1000 && in_data_rva((uint64_t)x->a->cval)) {
            char nm[48];
            std::snprintf(nm, sizeof nm, "qword_%llx", (unsigned long long)(uint64_t)x->a->cval);
            name = nm; return true;
        }
        return false;
    }
    static bool is_global_struct_name(const std::string& p) {
        return p.rfind("qword_", 0) == 0 || p.rfind("dword_", 0) == 0;
    }
    /* If `addr` is `param` / `(cast)param + CONST` / a global-base +CONST, return the
     * base name + byte offset. */
    bool struct_base_offset(const ExprP& addr, std::string& param, int64_t& off) {
        if (!addr) return false;
        if (addr->kind == EK::Var) { param = addr->name; off = 0; return is_ptr_param_name(param) || struct_var.count(param); }
        std::string gn;
        if (is_global_base(addr, gn)) { param = gn; off = 0; return true; }
        if (addr->kind == EK::Binary && addr->op == "+") {
            ExprP base = addr->a, idx = addr->b;
            if (!(idx && idx->kind == EK::Const)) {
                if (addr->a && addr->a->kind == EK::Const) { base = addr->b; idx = addr->a; }
                else return false;
            }
            if (!idx || idx->kind != EK::Const) return false;
            if (is_global_base(base, gn)) { param = gn; off = idx->cval; return true; }
            while (base && base->kind == EK::Cast) base = base->a;   /* strip (char*) etc. */
            if (base && base->kind == EK::Var && (is_ptr_param_name(base->name) || struct_var.count(base->name))) {
                param = base->name; off = idx->cval; return true;
            }
            /* G3: nested constant offset `(base + c1) + c2` — a `lea [p+c1]` whose temp
             * copy_propagate inlined into a later `[reg+c2]` access WITHOUT re-folding, so the
             * re-association fold (@~7724) never saw it. Resolve the inner base recursively and
             * ACCUMULATE the byte offset, so the access lands on the true field `(c1+c2)` and is
             * recovered/rendered `p->field_(c1+c2)` instead of the raw `&p->field_c1 + c2`. */
            if (base && base->kind == EK::Binary) {
                std::string ip; int64_t ioff;
                if (struct_base_offset(base, ip, ioff)) { param = ip; off = ioff + idx->cval; return true; }
            }
        }
        return false;
    }
    /* NESTED struct base (DS_NESTSTRUCT): `(char*)FL + K` (or bare FL, K=0) where FL is a
     * width-8 non-float field-LOAD `*(long long*)(<recovered struct field addr>)` used as a
     * pointer base. Returns a synthetic name `<parent>_<parentOffHex>` + the sub-offset K.
     * The parent must ALREADY be a recovered struct (param_structs populated), so this only
     * resolves in the SECOND recovery pass and at render time — never during the first
     * (top-level) collect. Disjoint from struct_base_offset: that requires a Var/global/
     * param+const base and REJECTS a Mem-load base, so nested and top-level never overlap. */
    bool nested_base_offset(const ExprP& addr, std::string& name, int64_t& off, int depth = 0) {
        static const bool disabled = std::getenv("DS_NO_NESTSTRUCT") != nullptr;
        /* deep chains stay clean because the fields are RETYPED `struct T*` — so
         * a1->f_28->f_22c8->f_23a renders as plain arrows, not stacked inline casts. */
        if (disabled || !addr || depth > 6) return false;   /* default-on; DS_NO_NESTSTRUCT disables */
        ExprP base = addr; off = 0;
        if (addr->kind == EK::Binary && addr->op == "+") {
            ExprP idx = addr->b; base = addr->a;
            if (!(idx && idx->kind == EK::Const)) {
                if (addr->a && addr->a->kind == EK::Const) { base = addr->b; idx = addr->a; }
                else return false;
            }
            if (!idx || idx->kind != EK::Const) return false;
            off = idx->cval;
        }
        ExprP fl = base;
        while (fl && fl->kind == EK::Cast) fl = fl->a;
        if (!fl || fl->kind != EK::Mem || !fl->a || fl->width != 8 || fl->is_float) return false;
        std::string pp; int64_t poff;
        /* the parent field-load's address resolves either to a TOP-LEVEL struct field, OR
         * (recursively) to a DEEPER nested struct field — so `a1->f_d0->f_x->f_y` chains to
         * any depth. The fixpoint collect below builds each level before the next needs it. */
        bool ok = struct_base_offset(fl->a, pp, poff);
        if (!ok) ok = nested_base_offset(fl->a, pp, poff, depth + 1);
        if (!ok) return false;
        auto it = param_structs.find(pp);
        if (it == param_structs.end() || !it->second.fw.count(poff)) return false;
        if (it->second.fw.at(poff) != 8) return false;                  /* pointer-sized field only */
        char nm[160]; std::snprintf(nm, sizeof nm, "%s_%llx", pp.c_str(), (unsigned long long)poff);
        name = nm; return true;
    }
    /* the field-load Mem at the root of a nested base, for rendering the `->` chain. */
    ExprP nested_base_load(const ExprP& addr) {
        ExprP base = addr;
        if (addr && addr->kind == EK::Binary && addr->op == "+")
            base = (addr->b && addr->b->kind == EK::Const) ? addr->a : addr->b;
        while (base && base->kind == EK::Cast) base = base->a;
        return base;
    }

    /* ---- ARRAY-OF-STRUCT recovery (DS_NO_ARRSTRUCT disables) ----
     * `*(T*)((char*)(index*stride + base) + off)` -> `((struct elem*)base)[index].field_off`,
     * where base is a struct-field-pointer / ptr-param, stride a constant element size, off a
     * constant field offset within an element. Inline-cast render (base keeps its type). */
    bool parse_index_scale(const ExprP& e, ExprP& idx, int64_t& stride) {
        ExprP x = e;
        while (x && x->kind == EK::Cast) x = x->a;
        if (!x || x->kind != EK::Binary || !x->b || x->b->kind != EK::Const) return false;
        if (x->op == "<<" && x->b->cval >= 3 && x->b->cval < 12) { idx = x->a; stride = (int64_t)1 << x->b->cval; return true; }
        if (x->op == "*"  && x->b->cval >= 8 && x->b->cval <= 0x1000) { idx = x->a; stride = x->b->cval; return true; }
        return false;
    }
    bool array_base_key(const ExprP& bs, std::string& key) {
        ExprP x = bs;
        while (x && x->kind == EK::Cast) x = x->a;
        if (!x) return false;
        if (x->kind == EK::Var && is_ptr_param_name(x->name)) { key = x->name; return true; }
        if (x->kind == EK::Mem && x->a && x->width == 8 && !x->is_float) {   /* a struct-field pointer load */
            std::string p; int64_t off;
            if (struct_base_offset(x->a, p, off) || nested_base_offset(x->a, p, off)) {
                char nm[176]; std::snprintf(nm, sizeof nm, "%s_%llx", p.c_str(), (unsigned long long)off);
                key = nm; return true;
            }
        }
        return false;
    }
    bool array_struct_access(const ExprP& mem, std::string& key, ExprP& base_out,
                             ExprP& index_out, int64_t& stride_out, int64_t& off_out) {
        static const bool disabled = std::getenv("DS_NO_ARRSTRUCT") != nullptr;
        if (disabled || !mem || mem->kind != EK::Mem || !mem->a) return false;
        ExprP a = mem->a; off_out = 0;
        if (a->kind == EK::Binary && a->op == "+" && a->b && a->b->kind == EK::Const) { off_out = a->b->cval; a = a->a; }
        while (a && a->kind == EK::Cast) a = a->a;
        if (!a || a->kind != EK::Binary || a->op != "+") return false;
        for (int sw = 0; sw < 2; ++sw) {
            ExprP si = sw ? a->b : a->a, bs = sw ? a->a : a->b;
            int64_t stride; ExprP idx;
            if (!parse_index_scale(si, idx, stride) || stride < 8) continue;
            if (off_out < 0 || off_out >= stride) continue;
            std::string bkey;
            if (!array_base_key(bs, bkey)) continue;
            char kk[220]; std::snprintf(kk, sizeof kk, "%s_A%llx", bkey.c_str(), (unsigned long long)stride);
            key = kk; base_out = bs; index_out = idx; stride_out = stride;
            return true;
        }
        return false;
    }
    void collect_array_struct(const ExprP& e,
            std::map<std::string,std::map<int64_t,int>>& fw,
            std::map<std::string,std::map<int64_t,bool>>& fu,
            std::map<std::string,std::map<int64_t,bool>>& ff,
            std::map<std::string,int64_t>& strides) {
        if (!e) return;
        if (e->kind == EK::Mem) {
            std::string key; ExprP b, i; int64_t stride, off;
            if (array_struct_access(e, key, b, i, stride, off)) {
                int w = e->width ? e->width : 1;
                auto& m = fw[key]; auto it = m.find(off);
                if (it == m.end()) { m[off] = w; fu[key][off] = e->is_unsigned; ff[key][off] = e->is_float; strides[key] = stride; }
                else if (it->second != w) it->second = -1;
            }
        }
        collect_array_struct(e->a, fw, fu, ff, strides);
        collect_array_struct(e->b, fw, fu, ff, strides);
        collect_array_struct(e->c, fw, fu, ff, strides);
        for (auto& a : e->args) collect_array_struct(a, fw, fu, ff, strides);
    }

    /* ---- POINTER-TEMP / STACK-LOCAL struct recovery (DS_NO_VARSTRUCT disables) ----
     * `*(T*)((char*)tN + K)` on a pointer temp / stack local accessed at >=2 fixed offsets
     * -> `((struct s*)tN)->field_K`. INLINE-CAST render (the var's declaration is NOT changed
     * — so its other uses, arithmetic, and `char sN[]` array-decay are all untouched). */
    std::set<std::string> struct_var;   /* pointer temps / stack locals recovered as struct bases */
    bool is_struct_base_candidate(const std::string& nm) {
        if (std::getenv("DS_NO_VARSTRUCT") || nm.size() < 2) return false;
        if (is_ptr_param_name(nm)) return false;             /* params handled separately */
        if (struct_excluded_params.count(nm)) return false;  /* used with a variable index -> array */
        auto vp = var_pointer.find(nm);
        if (vp != var_pointer.end() && vp->second) return true;   /* a pointer temp/var */
        if (array_locals.count(nm)) return true;                  /* a `char sN[]` stack local */
        return false;
    }
    bool var_struct_base(const ExprP& addr, std::string& name, int64_t& off) {
        if (!addr) return false;
        ExprP x = addr; while (x && x->kind == EK::Cast) x = x->a;
        if (x && x->kind == EK::Var && is_struct_base_candidate(x->name)) { name = x->name; off = 0; return true; }
        if (addr->kind == EK::Binary && addr->op == "+") {
            ExprP base = addr->a, idx = addr->b;
            if (!(idx && idx->kind == EK::Const)) {
                if (addr->a && addr->a->kind == EK::Const) { base = addr->b; idx = addr->a; }
                else return false;
            }
            if (!idx || idx->kind != EK::Const) return false;
            ExprP b = base; while (b && b->kind == EK::Cast) b = b->a;
            if (b && b->kind == EK::Var && is_struct_base_candidate(b->name)) { name = b->name; off = idx->cval; return true; }
        }
        return false;
    }
    /* mark a pointer-var / stack-local used with a VARIABLE index as an array (excluded). */
    void note_array_var(const ExprP& addr) {
        if (!addr || addr->kind != EK::Binary || addr->op != "+") return;
        if ((addr->b && addr->b->kind == EK::Const) || (addr->a && addr->a->kind == EK::Const)) return;
        for (int s = 0; s < 2; ++s) {
            ExprP side = s ? addr->b : addr->a, other = s ? addr->a : addr->b;
            ExprP b = side; while (b && b->kind == EK::Cast) b = b->a;
            if (b && b->kind == EK::Var && other && other->kind != EK::Const) {
                auto vp = var_pointer.find(b->name);
                if ((vp != var_pointer.end() && vp->second) || array_locals.count(b->name))
                    struct_excluded_params.insert(b->name);
            }
        }
    }
    void scan_var_array_excl(const ExprP& e) {
        if (!e) return;
        if (e->kind == EK::Mem && e->a) note_array_var(e->a);
        scan_var_array_excl(e->a); scan_var_array_excl(e->b); scan_var_array_excl(e->c);
        for (auto& a : e->args) scan_var_array_excl(a);
    }
    void collect_var_struct(const ExprP& e,
            std::map<std::string,std::map<int64_t,int>>& fw,
            std::map<std::string,std::map<int64_t,bool>>& fu,
            std::map<std::string,std::map<int64_t,bool>>& ff) {
        if (!e) return;
        if (e->kind == EK::Mem && e->a) {
            std::string p; int64_t off;
            if (var_struct_base(e->a, p, off) && off >= 0 && off < 0x8000) {
                int w = e->width ? e->width : 1;
                auto& m = fw[p]; auto it = m.find(off);
                if (it == m.end()) { m[off] = w; fu[p][off] = e->is_unsigned; ff[p][off] = e->is_float; }
                /* invalidate on a width OR float/non-float conflict: a slot accessed as both
                 * `*(float*)` and an int/pointer value can't be one typed field (a float
                 * field cast to `(T*)` is C2440). */
                else if (it->second != w || ff[p][off] != e->is_float) it->second = -1;
            }
        }
        collect_var_struct(e->a, fw, fu, ff);
        collect_var_struct(e->b, fw, fu, ff);
        collect_var_struct(e->c, fw, fu, ff);
        for (auto& a : e->args) collect_var_struct(a, fw, fu, ff);
    }
    std::set<std::string> struct_excluded_params;   /* array-indexed -> not a struct */
    std::set<std::string> array_accessed_params;     /* G2: variable-indexed params; excluded only if they have <4 fixed fields (else a struct w/ a trailing array) */
    /* A param used with a VARIABLE index (`a1[i]`, `*(T*)((char*)a1 + i*s)`) is an
     * ARRAY, not a struct — exclude it (retyping it `struct*` would break `a1[i]`). */
    void note_array_param(const ExprP& addr) {
        if (!addr || addr->kind != EK::Binary || addr->op != "+") return;
        ExprP base = addr->a, idx = addr->b;
        if (idx && idx->kind == EK::Const) return;               /* const offset = field */
        if (addr->a && addr->a->kind == EK::Const) return;
        while (base && base->kind == EK::Cast) base = base->a;
        if (base && base->kind == EK::Var && is_ptr_param_name(base->name))
            array_accessed_params.insert(base->name);   /* G2: defer exclusion to field-count check */
        /* also `idx*scale + param` shapes: check both operands for a param base */
        ExprP other = addr->b;
        while (other && other->kind == EK::Cast) other = other->a;
        if (other && other->kind == EK::Var && is_ptr_param_name(other->name) &&
            addr->a && addr->a->kind != EK::Const)
            array_accessed_params.insert(other->name);
    }
    void collect_struct_access(const ExprP& e,
            std::map<std::string,std::map<int64_t,int>>& fw,
            std::map<std::string,std::map<int64_t,bool>>& fu,
            std::map<std::string,std::map<int64_t,bool>>& ff) {
        if (!e) return;
        if (e->kind == EK::Mem && e->a) {
            std::string p; int64_t off;
            if (struct_base_offset(e->a, p, off) && off >= 0 && off < 0x8000) {
                int w = e->width ? e->width : 1;
                auto& m = fw[p]; auto it = m.find(off);
                if (it == m.end()) { m[off] = w; fu[p][off] = e->is_unsigned; ff[p][off] = e->is_float; }
                else if (it->second != w) it->second = -1;   /* width conflict -> invalidate */
            } else note_array_param(e->a);
        }
        collect_struct_access(e->a, fw, fu, ff);
        collect_struct_access(e->b, fw, fu, ff);
        collect_struct_access(e->c, fw, fu, ff);
        for (auto& a : e->args) collect_struct_access(a, fw, fu, ff);
    }
    /* second-pass collector keyed on nested_base_offset (a1->field_d0->field_K). */
    void collect_nested_access(const ExprP& e,
            std::map<std::string,std::map<int64_t,int>>& fw,
            std::map<std::string,std::map<int64_t,bool>>& fu,
            std::map<std::string,std::map<int64_t,bool>>& ff) {
        if (!e) return;
        if (e->kind == EK::Mem && e->a) {
            std::string p; int64_t off;
            if (nested_base_offset(e->a, p, off) && off >= 0 && off < 0x8000) {
                int w = e->width ? e->width : 1;
                auto& m = fw[p]; auto it = m.find(off);
                if (it == m.end()) { m[off] = w; fu[p][off] = e->is_unsigned; ff[p][off] = e->is_float; }
                else if (it->second != w) it->second = -1;
            }
        }
        collect_nested_access(e->a, fw, fu, ff);
        collect_nested_access(e->b, fw, fu, ff);
        collect_nested_access(e->c, fw, fu, ff);
        for (auto& a : e->args) collect_nested_access(a, fw, fu, ff);
    }
    void recover_struct_layouts() {
        std::map<std::string,std::map<int64_t,int>>  fw;
        std::map<std::string,std::map<int64_t,bool>> fu, ff;
        struct_field_ptr.clear();
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { collect_struct_access(s.lhs, fw, fu, ff);
                                      collect_struct_access(s.rhs, fw, fu, ff); }
            collect_struct_access(b.cond, fw, fu, ff);
            collect_struct_access(b.ret_value, fw, fu, ff);
            collect_struct_access(b.switch_var, fw, fu, ff);
            collect_struct_access(b.tail_call, fw, fu, ff);
        }
        /* G4: type a qword field whose LOADED VALUE is used as an address base as `void*`.
         * scan_field_ptr populates struct_field_ptr[p]; the fptr build below (`w==8 && !ff &&
         * pptr.count(o)`) then marks the field, struct_typedef_str emits `void*`, and
         * is_struct_ptr_field activates the uniform byte-cast render machinery (the nested-
         * struct feature added it to rptr/typed_ptr/render_addr; a G4 audit closed the
         * remaining void*-specific gaps: expr_is_pointer Mem arm, the float-const-offset
         * arith branches above, and the float-store-into-field reinterpret). scan_field_ptr
         * uses struct_base_offset which never reads param_structs, so running it in this first
         * pass (before param_structs is built) is correct. Gated DS_NO_FIELDPTR for A/B bisect. */
        if (!std::getenv("DS_NO_FIELDPTR")) {
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { scan_field_ptr(s.lhs); scan_field_ptr(s.rhs); }
                scan_field_ptr(b.cond);
                scan_field_ptr(b.ret_value);
                scan_field_ptr(b.switch_var);
                scan_field_ptr(b.tail_call);
            }
        }
        /* G2: a variable-indexed param is normally an array. But if it ALSO has >=4
         * distinct fixed-offset fields it is really a STRUCT (a constructor/initializer),
         * and Hex-Rays recovers those fields — the one variable access just stays byte-
         * cast (is_ptr_base excludes param_structs). Only exclude the ambiguous few-field
         * case. Computed here (after collect) so the field counts are final. */
        for (auto& p : array_accessed_params) {
            int nfixed = 0; auto it = fw.find(p);
            if (it != fw.end()) for (auto& o : it->second) if (o.second > 0) ++nfixed;
            if (nfixed < 4) struct_excluded_params.insert(p);
        }
        /* CLASS RECONSTRUCTION: a struct whose field_0 is WRITTEN a known RTTI vtable
         * address (`*obj = &<Class>__vftable`, i.e. a constructor) IS that C++ class.
         * Name its tag after the class (`struct GameManager`) instead of `s_<fn>_<param>`,
         * so decompiled output reads like Hex-Rays class recovery. class_for_vtable maps the
         * stored constant back to the class via the `<Class>__vftable` symbol rtti.cpp seeded.
         * The base var need not be a recovered param/struct_var yet (a ctor's object is a
         * fresh `operator new` temp), so extract the base name directly. */
        std::map<std::string,std::string> struct_class;      /* base -> sani'd C tag (game__Entity) */
        std::map<std::string,std::string> struct_class_qual; /* base -> RAW qualified name (game::Entity) */
        std::map<std::string,bool> struct_class_kw;          /* base -> RTTI kind is-struct (else class) */
        auto vtable_base = [](const ExprP& lhs, std::string& base) -> bool {
            if (!lhs || lhs->kind != EK::Mem || !lhs->a) return false;
            ExprP a = lhs->a;
            while (a && a->kind == EK::Cast) a = a->a;
            if (a && a->kind == EK::Var) { base = a->name; return true; }   /* *(T*)base */
            if (a && a->kind == EK::Binary && a->op == "+" && a->b &&
                a->b->kind == EK::Const && a->b->cval == 0) {               /* *(T*)(base+0) */
                ExprP bb = a->a; while (bb && bb->kind == EK::Cast) bb = bb->a;
                if (bb && bb->kind == EK::Var) { base = bb->name; return true; }
            }
            return false;
        };
        {
            auto scan_vt = [&](const ExprP& lhs, const ExprP& rhs) {
                if (!lhs || !rhs) return;
                ExprP r = rhs; while (r && r->kind == EK::Cast) r = r->a;
                if (!r || r->kind != EK::Const) return;
                bool is_struct = false;
                std::string cls_raw = class_for_vtable((uint64_t)r->cval, &is_struct);   /* raw qualified */
                if (cls_raw.empty()) return;
                std::string base;
                if (vtable_base(lhs, base)) {
                    struct_class[base] = sani(cls_raw); struct_class_qual[base] = cls_raw;
                    struct_class_kw[base] = is_struct;
                }
            };
            for (auto& b : blocks) for (auto& s : b.stmts)
                if (s.kind == SK::Assign) scan_vt(s.lhs, s.rhs);
        }
        /* VIRTUAL-METHOD `this` TYPING (DS_NO_VMTHIS): a recovered vmethod `<Class>__vftbl_N`
         * has a1 == this == <Class> -- the exact assumption resolve_virtual_call already trusts.
         * The RTTI scanner named the fn but never typed the receiver, so a1 renders as a bare
         * int64_t pointer with a1[k] instead of arrowing through the recovered class layout.
         * Reject the `_off<digits>` MI
         * subobject form (its this is a base subobject ptr, not the class base). */
        if (!std::getenv("DS_NO_VMTHIS") && !struct_class.count("a1")) {
            size_t vp = self_fname.find("__vftbl_");
            if (vp != std::string::npos && vp > 0) {
                std::string ctag = self_fname.substr(0, vp);
                bool mi = false;
                size_t op = ctag.rfind("_off");
                if (op != std::string::npos && op + 4 < ctag.size()) {
                    mi = true;
                    for (size_t k = op + 4; k < ctag.size(); ++k)
                        if (!isdigit((unsigned char)ctag[k])) { mi = false; break; }
                }
                std::string qual; bool isst = false;
                if (!mi && class_qual_for_tag(ctag, qual, isst)) {
                    struct_class["a1"] = ctag;
                    struct_class_qual["a1"] = qual;
                    struct_class_kw["a1"] = isst;
                    if (!fw["a1"].count(0)) { fw["a1"][0] = 8; fu["a1"][0] = false; ff["a1"][0] = false; }
                }
            }
        }
        /* Vec2/Vec3/Vec4: a by-pointer struct that is EXACTLY 2/3/4 contiguous width-4
         * FLOAT fields at offsets 0,4,8,12 is a math vector — name it Vec<N> (a shared,
         * include-guarded typedef) instead of the opaque per-fn `s_<fn>_<p>`. */
        auto is_vec_layout = [&](const ParamStruct& L) -> int {
            size_t n = L.fw.size();
            if (n < 2 || n > 4 || L.stride != 0) return 0;
            int64_t exp = 0;
            for (auto& kv : L.fw) {
                if (kv.first != exp || kv.second != 4) return 0;   /* contiguous, width-4 */
                auto f = L.ff.find(kv.first);
                if (f == L.ff.end() || !f->second) return 0;       /* must be float */
                if (L.fptr.count(kv.first) && L.fptr.at(kv.first)) return 0;
                exp += 4;
            }
            return (int)n;
        };
        auto mktag = [&](const std::string& p, ParamStruct& L) {
            auto it = struct_class.find(p);
            if (it != struct_class.end()) { L.tag = it->second; L.is_class = true;
                                            L.cls_kw_struct = struct_class_kw.count(p) && struct_class_kw[p];
                                            if (struct_class_qual.count(p)) L.qual_name = struct_class_qual[p]; return; }
            if (int vn = is_vec_layout(L)) { L.tag = "Vec" + std::to_string(vn); L.shared_typedef = true; return; }
            /* GLOBAL-STRUCT UNIFICATION: a global data object at a fixed address is ONE type
             * for the whole program. Tag it by its ADDRESS (g_<addr>), not the per-function
             * name, and shared_typedef-guard the definition, so every function that touches
             * qword_<addr> names the SAME struct instead of a private s_<fn>_qword_<addr>.
             * (Each function still only declares the fields IT sees; the NullWare gate compiles
             * every function as its own TU so that is always sound. DS_NO_GUNIFY reverts.) */
            /* Only a REAL top-level global (`qword_<hex>` / `dword_<hex>` whose suffix is pure
             * hex with NO further '_') is one program-wide type worth unifying. A NESTED or
             * ARRAY-element derivative (`qword_<hex>_<off>`, `..._A<stride>`) is a per-function
             * synthetic whose layout is context-specific -- unifying those under a shared,
             * guarded tag made a later view miss the first view's fields (C2039). This mirrors
             * the same real-vs-synthetic test in assign_global_struct_locals. */
            if (is_global_struct_name(p) && p.size() > 6 &&
                p.substr(6).find('_') == std::string::npos && !std::getenv("DS_NO_GUNIFY")) {
                /* Tag by the FULL base name (`g_qword_140050`), not just the address: the same
                 * address read at two widths mints both qword_<addr> and dword_<addr> with
                 * different layouts, so the qword/dword prefix must stay to keep them distinct
                 * while still unifying each across every function. */
                L.tag = "g_" + p;
                L.shared_typedef = true;
                return;
            }
            L.tag = "s_" + self_fname + "_" + p;
        };
        for (auto& kv : fw) {
            const std::string& p = kv.first;
            if (struct_excluded_params.count(p)) continue;   /* array param, not a struct */
            std::vector<int64_t> offs;
            for (auto& o : kv.second) if (o.second > 0) offs.push_back(o.first);
            std::sort(offs.begin(), offs.end());
            ParamStruct L; int64_t prev_end = -1;
            auto& pptr = struct_field_ptr[p];
            for (int64_t o : offs) {
                int w = kv.second[o];
                if (o < prev_end) continue;             /* overlaps previous field -> skip */
                L.fw[o] = w; L.fu[o] = fu[p][o]; L.ff[o] = ff[p][o];
                /* a qword field whose value is used as a base address is a pointer */
                L.fptr[o] = (w == 8 && !ff[p][o] && pptr.count(o));
                prev_end = o + w;
            }
            /* tag qualified by the function name so concatenated pair-files (the corpus
             * builds one TU per DLL) don't collide on `struct s_a1`. */
            if (L.fw.size() >= 2) { mktag(p, L); param_structs[p] = L; }
        }
        /* SECOND PASS: nested struct-pointer fields (a1->field_d0->field_K). Runs AFTER the
         * top-level structs exist (nested_base_offset validates the parent field against
         * param_structs). Inline-cast render — the field stays `long long`, so no field is
         * retyped and no pointer arithmetic breaks (unlike the reverted #32). */
        if (!std::getenv("DS_NO_NESTSTRUCT")) {
            /* fixpoint: level 0 builds depth-2 structs (parent = a top-level field), level 1
             * builds depth-3 (parent = a depth-2 nested field), ... until no new level. */
            for (int level = 0; level < 6; ++level) {
                std::map<std::string,std::map<int64_t,int>>  nfw;
                std::map<std::string,std::map<int64_t,bool>> nfu, nff;
                for (auto& b : blocks) {
                    for (auto& s : b.stmts) { collect_nested_access(s.lhs, nfw, nfu, nff);
                                              collect_nested_access(s.rhs, nfw, nfu, nff); }
                    collect_nested_access(b.cond, nfw, nfu, nff);
                    collect_nested_access(b.ret_value, nfw, nfu, nff);
                    collect_nested_access(b.switch_var, nfw, nfu, nff);
                    collect_nested_access(b.tail_call, nfw, nfu, nff);
                }
                int added = 0;
                for (auto& kv : nfw) {
                    const std::string& p = kv.first;
                    if (param_structs.count(p)) continue;      /* already built (earlier level) */
                    std::vector<int64_t> offs;
                    for (auto& o : kv.second) if (o.second > 0) offs.push_back(o.first);
                    std::sort(offs.begin(), offs.end());
                    ParamStruct L; int64_t prev_end = -1;
                    for (int64_t o : offs) {
                        int w = kv.second[o];
                        if (o < prev_end) continue;
                        L.fw[o] = w; L.fu[o] = nfu[p][o]; L.ff[o] = nff[p][o]; L.fptr[o] = false;
                        prev_end = o + w;
                    }
                    if (L.fw.size() >= 2) {
                        mktag(p, L); param_structs[p] = L; added++;
                        /* RETYPE the parent field as `struct <thisTag>*` so accesses through
                         * it render as clean arrows (a1->f_28->f_K) instead of inline casts.
                         * The synthetic name is `<parent>_<offHex>`; the parent is already a
                         * recovered struct (nested was collected after it). */
                        auto us = p.rfind('_');
                        if (us != std::string::npos && us + 1 < p.size()) {
                            std::string parent = p.substr(0, us);
                            int64_t poff = (int64_t)strtoll(p.substr(us + 1).c_str(), nullptr, 16);
                            auto pit = param_structs.find(parent);
                            if (pit != param_structs.end() && pit->second.fw.count(poff) &&
                                pit->second.fw.at(poff) == 8) {
                                pit->second.fptr[poff] = true;
                                pit->second.fptr_tag[poff] = L.tag;
                            }
                        }
                    }
                }
                if (added == 0) break;                         /* no new nesting level exposed */
            }
        }
        /* ARRAY-OF-STRUCT: element structs for `base + index*stride + off` field accesses.
         * The element struct is padded to `stride` so `((struct elem*)base)[i]` addresses
         * `base + i*stride`. Runs after nested so a nested base pointer resolves. */
        if (!std::getenv("DS_NO_ARRSTRUCT")) {
            std::map<std::string,std::map<int64_t,int>>  afw;
            std::map<std::string,std::map<int64_t,bool>> afu, aff;
            std::map<std::string,int64_t> astr;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { collect_array_struct(s.lhs, afw, afu, aff, astr);
                                          collect_array_struct(s.rhs, afw, afu, aff, astr); }
                collect_array_struct(b.cond, afw, afu, aff, astr);
                collect_array_struct(b.ret_value, afw, afu, aff, astr);
                collect_array_struct(b.switch_var, afw, afu, aff, astr);
                collect_array_struct(b.tail_call, afw, afu, aff, astr);
            }
            for (auto& kv : afw) {
                const std::string& p = kv.first;
                if (param_structs.count(p)) continue;
                std::vector<int64_t> offs;
                for (auto& o : kv.second) if (o.second > 0) offs.push_back(o.first);
                std::sort(offs.begin(), offs.end());
                ParamStruct L; int64_t prev_end = -1;
                for (int64_t o : offs) {
                    int w = kv.second[o];
                    if (o < prev_end) continue;
                    L.fw[o] = w; L.fu[o] = afu[p][o]; L.ff[o] = aff[p][o]; L.fptr[o] = false;
                    prev_end = o + w;
                }
                /* require >=2 distinct fields OR the stride would just be a scalar array. */
                if (L.fw.size() >= 2 && prev_end <= astr[p]) {
                    mktag(p, L); L.stride = astr[p];
                    param_structs[p] = L;
                }
            }
        }
        /* POINTER-TEMP / STACK-LOCAL structs (runs last; struct_var seeds the render only,
         * after the higher-precedence param/global/nested/array structs are built). */
        if (!std::getenv("DS_NO_VARSTRUCT")) {
            for (auto& b : blocks) {                             /* pass 1: exclude array vars */
                for (auto& s : b.stmts) { scan_var_array_excl(s.lhs); scan_var_array_excl(s.rhs); }
                scan_var_array_excl(b.cond); scan_var_array_excl(b.ret_value);
                scan_var_array_excl(b.switch_var); scan_var_array_excl(b.tail_call);
            }
            std::map<std::string,std::map<int64_t,int>>  vfw;
            std::map<std::string,std::map<int64_t,bool>> vfu, vff;
            for (auto& b : blocks) {                             /* pass 2: collect const-offset fields */
                for (auto& s : b.stmts) { collect_var_struct(s.lhs, vfw, vfu, vff);
                                          collect_var_struct(s.rhs, vfw, vfu, vff); }
                collect_var_struct(b.cond, vfw, vfu, vff);
                collect_var_struct(b.ret_value, vfw, vfu, vff);
                collect_var_struct(b.switch_var, vfw, vfu, vff);
                collect_var_struct(b.tail_call, vfw, vfu, vff);
            }
            for (auto& kv : vfw) {
                const std::string& p = kv.first;
                if (param_structs.count(p)) continue;
                std::vector<int64_t> offs;
                for (auto& o : kv.second) if (o.second > 0) offs.push_back(o.first);
                std::sort(offs.begin(), offs.end());
                ParamStruct L; int64_t prev_end = -1;
                for (int64_t o : offs) {
                    int w = kv.second[o];
                    if (o < prev_end) continue;
                    L.fw[o] = w; L.fu[o] = vfu[p][o]; L.ff[o] = vff[p][o]; L.fptr[o] = false;
                    prev_end = o + w;
                }
                /* An all-single-byte layout on a POINTER TEMP is a char / uint8_t
                 * buffer walked as a string (`p[0],p[1],p[2]`), not a struct --
                 * synthesizing `struct{int8 f0,f1,f2}` is the phantom-struct-for-a-
                 * byte-string artifact. Leave it a plain byte pointer;
                 * propagate_pointer_types (already run) typed such a temp `uint8_t*`
                 * (element width 1), so its const-offset accesses render as `p[k]`.
                 * DS_KEEP_BYTESTRUCT restores the old struct form for A/B. */
                bool all_bytes = true;
                for (auto& f : L.fw) if (f.second != 1) { all_bytes = false; break; }
                bool byte_str = all_bytes && !std::getenv("DS_KEEP_BYTESTRUCT");
                if (L.fw.size() >= 2 && !byte_str) {
                    mktag(p, L); param_structs[p] = L; struct_var.insert(p);
                }
            }
        }

    }

    /* STRUCT UNIFICATION -- BUILT, MEASURED ZERO, REVERTED (2026-07-17). Do not rebuild it
     * the same way; the numbers are here so the next attempt starts from them.
     *
     * The idea: every struct is tagged per VARIABLE (s_<fn>_v54, s_<fn>_v2), so two pointers
     * to the SAME real struct get DIFFERENT type names, and the output asserts a distinction
     * the program does not have:
     *     struct s_fun_00009550_v54*v54;
     *     struct s_fun_00009550_v2 *v2;
     *     while ((int64_t)(v54) != (int64_t)(v2))   <- a cast the source never needed
     *
     * The SOUND criterion is the assignment/compare, not the shape: two structs sharing a
     * recovered layout proves nothing ({int64_t; int64_t} is a vector, a pair, a node), while
     * code comparing them does not compile across unrelated struct types in the original
     * source. Requiring BOTH (evidence AND identical layout) is what I implemented, and it
     * fires ZERO times -- measured over 300 functions:
     *     struct-var compares across different tags : 2
     *     ...of those with identical layouts        : 0
     * and the 0 is structural, not bad luck: each variable only reveals the fields IT
     * touches, so two views of one type ALWAYS have different layouts. The two conditions are
     * a contradiction.
     *
     * (I reached that pair count by measuring '48 identical duplicate layouts' and 'compares
     * exist' SEPARATELY and assuming the intersection was non-empty -- the same mistake the
     * devirt recon caught itself making. Measure the INTERSECTION.)
     *
     * WHAT WOULD ACTUALLY WORK: on evidence alone, UNION the two field sets -- v54 and v2 are
     * one type, so the real struct has both their fields, and the merged view is strictly
     * more complete than either. That is a genuine feature. It is also only ~2 sites per 300
     * functions here, and unioning fields can create overlaps that corrupt every offset, so
     * it needs its own cycle and a fixture -- not a drive-by. */

    /* STRUCT UNIFICATION (field UNION on proven aliasing) -- the "WHAT WOULD ACTUALLY WORK"
     * above, now built with the overlap/conflict guard it needed. Two per-function pointer
     * structs whose bases the code PROVES are the same object -- a pointer copy `v2 = v54`, an
     * equality/inequality compare `v54 == v2`, or both passed to the SAME parameter slot of the
     * SAME callee -- are ONE type: they get a shared tag and the UNION of their fields, so every
     * access renders through one complete struct and the bogus `(int64_t)v54 != (int64_t)v2`
     * cross-type cast disappears. SOUND: only proven aliases merge, and any field disagreement
     * at a shared offset (different width / float-ness / pointer-ness / nested tag) or a
     * resulting overlap ABORTS that group rather than corrupting a layout. Only plain top-level
     * param / local struct bases participate (never a class/vector/string/nested/array/global
     * type, which already has its own identity). DS_NO_STRUCTUNIFY. */
    void unify_struct_aliases() {
        if (std::getenv("DS_NO_STRUCTUNIFY")) return;
        if (param_structs.size() < 2) return;
        const std::string pfx = "s_" + self_fname + "_";
        auto eligible = [&](const std::string& p) -> bool {
            if (!(is_ptr_param_name(p) || struct_var.count(p))) return false;   /* top-level only */
            auto it = param_structs.find(p);
            if (it == param_structs.end()) return false;
            const ParamStruct& L = it->second;
            if (L.is_class || L.is_vector || L.is_stdstring || L.shared_typedef || L.stride != 0)
                return false;                                   /* already-canonical / array elem */
            return L.tag.rfind(pfx, 0) == 0;                    /* a plain s_<fn>_<p> tag */
        };
        std::map<std::string,std::string> parent;
        std::function<std::string(const std::string&)> find = [&](const std::string& x) -> std::string {
            auto it = parent.find(x);
            if (it == parent.end()) { parent[x] = x; return x; }
            if (it->second == x) return x;
            return parent[x] = find(it->second);
        };
        auto unite = [&](const std::string& a, const std::string& b) {
            if (a == b || !eligible(a) || !eligible(b)) return;
            std::string ra = find(a), rb = find(b);
            if (ra != rb) parent[ra] = rb;
        };
        auto base_var = [](const ExprP& e) -> std::string {
            ExprP x = e; while (x && x->kind == EK::Cast) x = x->a;
            return (x && x->kind == EK::Var) ? x->name : std::string();
        };
        std::map<std::string,std::string> call_arg;             /* "callee#pos" -> first eligible arg var */
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Binary && (e->op == "==" || e->op == "!=")) {
                std::string a = base_var(e->a), b = base_var(e->b);
                if (!a.empty() && !b.empty()) unite(a, b);      /* compare aliasing */
            }
            if (e->kind == EK::Call && !e->callee.empty()) {
                for (size_t k = 0; k < e->args.size(); ++k) {
                    std::string v = base_var(e->args[k]);
                    if (v.empty() || !eligible(v)) continue;
                    std::string key = e->callee + "#" + std::to_string(k);
                    auto it = call_arg.find(key);
                    if (it == call_arg.end()) call_arg[key] = v; /* same callee + same argpos */
                    else unite(it->second, v);
                }
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                if (s.kind == SK::Assign && s.lhs && s.rhs) {
                    std::string a = base_var(s.lhs), r = base_var(s.rhs);
                    if (!a.empty() && !r.empty()) unite(a, r);   /* pointer-copy aliasing */
                }
                scan(s.lhs); scan(s.rhs);
            }
            scan(b.cond); scan(b.ret_value); scan(b.switch_var); scan(b.tail_call);
        }
        /* group members by union root */
        std::map<std::string, std::vector<std::string>> groups;
        for (auto& kv : param_structs)
            if (eligible(kv.first)) groups[find(kv.first)].push_back(kv.first);
        for (auto& g : groups) {
            auto& members = g.second;
            if (members.size() < 2) continue;
            std::map<int64_t,int>  mfw;
            std::map<int64_t,bool> mfu, mff, mfptr;
            std::map<int64_t,std::string> mfptr_tag;
            bool ok = true;
            for (auto& m : members) {
                const ParamStruct& L = param_structs[m];
                for (auto& kv : L.fw) {
                    int64_t o = kv.first; int w = kv.second;
                    bool fu = L.fu.count(o) ? L.fu.at(o) : false;
                    bool ff = L.ff.count(o) ? L.ff.at(o) : false;
                    bool fp = L.fptr.count(o) ? L.fptr.at(o) : false;
                    std::string ft = L.fptr_tag.count(o) ? L.fptr_tag.at(o) : "";
                    auto it = mfw.find(o);
                    if (it == mfw.end()) {
                        mfw[o] = w; mfu[o] = fu; mff[o] = ff; mfptr[o] = fp;
                        if (!ft.empty()) mfptr_tag[o] = ft;
                    } else {
                        std::string mft = mfptr_tag.count(o) ? mfptr_tag[o] : "";
                        /* signedness (fu) difference is benign; everything else aborts. */
                        if (it->second != w || mff[o] != ff || mfptr[o] != fp || mft != ft) { ok = false; break; }
                    }
                }
                if (!ok) break;
            }
            if (!ok) continue;
            int64_t prev_end = -1;                              /* reject any overlap */
            for (auto& kv : mfw) {
                if (kv.first < prev_end) { ok = false; break; }
                prev_end = kv.first + kv.second;
            }
            if (!ok) continue;
            /* canonical = member with the most fields (ties -> lexicographically smallest). */
            std::string canon = members.front();
            for (auto& m : members)
                if (param_structs[m].fw.size() > param_structs[canon].fw.size() ||
                    (param_structs[m].fw.size() == param_structs[canon].fw.size() && m < canon))
                    canon = m;
            std::string tag = param_structs[canon].tag;
            for (auto& m : members) {                           /* shared tag + unioned fields */
                ParamStruct& L = param_structs[m];
                L.tag = tag; L.fw = mfw; L.fu = mfu; L.ff = mff; L.fptr = mfptr; L.fptr_tag = mfptr_tag;
            }
        }
    }

    /* SELF-REFERENTIAL (linked-list / tree) struct fields. A width-8 field O of struct S
     * whose loaded value is used as a base of S itself is a next/prev/child link. The
     * list-iteration `v = *(long long*)(v + O)` -- reassigning the SAME struct variable
     * from its own field O -- is the clean, sound signal: offset O of v's struct points to
     * v's struct. Retype it as `struct <S>*` (fptr_tag = S's own tag) so `v = v->field_O`
     * and `v->field_O->field_K` render as arrow chains instead of raw casts, and the struct
     * definition self-references (`struct S { ...; struct S* field_O; }`, legal C). Runs
     * AFTER the layouts + unification are final so the tag is canonical. DS_NO_LISTSTRUCT. */
    void detect_self_ref_fields() {
        if (std::getenv("DS_NO_LISTSTRUCT")) return;
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
                const std::string& v = s.lhs->name;
                auto it = param_structs.find(v);
                if (it == param_structs.end()) continue;        /* lhs must be a recovered struct base */
                ParamStruct& L = it->second;
                if (L.is_class || L.is_vector || L.is_stdstring || L.shared_typedef) continue;
                ExprP r = s.rhs;
                while (r && r->kind == EK::Cast) r = r->a;       /* strip (struct S*) etc. */
                if (!r || r->kind != EK::Mem || !r->a || r->width != 8 || r->is_float) continue;
                std::string p; int64_t off;
                if (!struct_base_offset(r->a, p, off)) continue;
                if (p != v) continue;                            /* load must be from v's OWN field */
                auto fw = L.fw.find(off);
                if (fw == L.fw.end() || fw->second != 8) continue;   /* offset O is a width-8 field */
                if (L.ff.count(off) && L.ff.at(off)) continue;   /* never retype a float field */
                L.fptr[off] = true;
                L.fptr_tag[off] = L.tag;                          /* struct S* -- self reference */
            }
        }
    }

    /* Cache each READ-ONLY global struct base in a typed local (`struct s* gs_X = (struct
     * s*)qword_X;`) so the body reads `gs_X->field` instead of repeating the ~50-char
     * `((struct s*)qword_X)->` at every access (fn_0001ab40 has 387 of ONE such cast).
     * SKIP a global the function writes mid-body — a cached copy would go stale (the
     * inline form re-reads `*(long long*)0xX` each time, preserving that semantics). */
    void assign_global_struct_locals() {
        if (std::getenv("DS_NO_GSLOCAL")) return;
        auto writes_addr = [&](uint64_t addr) -> bool {
            for (auto& b : blocks)
                for (auto& s : b.stmts) {
                    if (s.kind != SK::Assign || !s.lhs) continue;
                    ExprP x = s.lhs;
                    while (x && x->kind == EK::Cast) x = x->a;
                    if (x && x->kind == EK::Mem && x->a && x->a->kind == EK::Const &&
                        (uint64_t)x->a->cval == addr && x->width == 8)
                        return true;
                }
            return false;
        };
        for (auto& kv : param_structs) {
            const std::string& p = kv.first;
            if (!is_global_struct_name(p)) continue;
            /* skip a NESTED synthetic name (`qword_X_Y`) — only a REAL global (`qword_<hex>`,
             * a #define'd data address) can seed a local; its suffix is pure hex, no '_'. */
            if (p.substr(6).find('_') != std::string::npos) continue;
            uint64_t addr = strtoull(p.c_str() + 6, nullptr, 16);
            if (!writes_addr(addr)) global_struct_local[p] = "gs_" + p.substr(6);
        }
    }
    std::string struct_typedef_str(const ParamStruct& L) {
        /* A class-named struct (RTTI recovery) uses the bare class name as its tag, so
         * concatenating many decompiled functions into one TU would redefine it (C2011).
         * Guard the definition like the __DS_FABS_DEFINED intrinsics: first definition wins,
         * later identical ones are skipped. (Per-function `s_<fn>_<param>` tags are already
         * unique, so they are never guarded.) */
        std::string guard;
        if (L.is_class) { guard = "__DS_CLS_" + L.tag; }
        else if (L.shared_typedef) { guard = "__DS_TY_" + L.tag; }   /* Vec2/3/4: one definition per TU */
        /* RTTI recovery emits the ORIGINAL keyword: `class` for a V-tagged type, `struct` for a
         * U/T-tagged one. `class` is C++-only, so a `#ifndef __cplusplus #define class struct` shim
         * (emitted once per TU by the caller) keeps the /TC recompile valid — members are all-public
         * so class/struct are identical. */
        std::string kw = (L.is_class && !L.cls_kw_struct) ? "class" : "struct";
        /* RTTI-recovered direct base, as a comment (`: Base` is C++, units compile /TC). */
        std::string base_cmt;
        if (L.is_class) { std::string bb = class_base_of(L.tag); if (!bb.empty()) base_cmt = " /* : " + bb + " */"; }
        /* build the field-body interior ONCE (padding + fields; field_0 of a class -> `void* __vftable`). */
        std::string body; int64_t pos = 0;
        /* Merge the width-recovered fields (fw) with the API-typed fields (ftype, e.g. a
         * CRITICAL_SECTION), in offset order. An ftype field reserves its full byte size and
         * suppresses any fw entries that fall inside it. */
        std::map<int64_t,int> merged;
        for (auto& kv : L.fw) merged[kv.first] = kv.second;
        for (auto& kv : L.ftype) merged[kv.first] = kv.second.second;   /* size wins at that offset */
        for (auto& kv : merged) {
            int64_t off = kv.first; int w = kv.second;
            if (off < pos) continue;                          /* inside a wider (ftype) field */
            if (off > pos) body += "    char _pad_" + hex(pos).substr(2) + "[" +
                                   std::to_string((long long)(off - pos)) + "];\n";
            auto ftit = L.ftype.find(off);
            if (ftit != L.ftype.end()) {                      /* API-named field (CRITICAL_SECTION) */
                body += "    " + ftit->second.first + " " + fld(L, off) + ";\n";
                pos = off + ftit->second.second;
                continue;
            }
            if (L.is_class && off == 0 && w == 8) { body += "    void* __vftable;\n"; pos = w; continue; }
            std::string ty;
            if (L.fptr_tag.count(off)) ty = "struct " + L.fptr_tag.at(off) + "*";
            else if (L.fptr.count(off) && L.fptr.at(off)) ty = "void*";
            else ty = L.ff.at(off) ? (w >= 8 ? "double" : "float") : typ_str(w, L.fu.at(off), false);
            body += "    " + ty + " " + fld(L, off) + ";\n";
            pos = off + w;
        }
        if (L.stride > pos)
            body += "    char _pad_end[" + std::to_string((long long)(L.stride - pos)) + "];\n";

        std::string s;
        if (L.is_vector) s += "/* std::vector — _Myfirst=begin, _Mylast=end, _Myend=capacity; size()=(_Mylast-_Myfirst)/sizeof(T) */\n";
        if (L.is_stdstring) s += "/* std::string (MSVC SSO) — _Myres <= 15: _Bx is the inline char[16]; else _Bx is a char* to the heap block. _Mysize=length */\n";
        if (!guard.empty()) s += "#ifndef " + guard + "\n#define " + guard + "\n";
        auto flat = [&]{ return "#pragma pack(push, 1)\n" + kw + " " + L.tag + base_cmt + " {\n" + body + "};\n#pragma pack(pop)\n"; };
        /* NAMESPACE: a namespaced RTTI name (game::Entity) dual-emits — a REAL
         * `namespace game { class Entity {...}; }` block under #ifdef __cplusplus (for reading / a
         * /TP recompile), and the flat `<kw> <tag> {...}` under #else which is what the /TC gate
         * compiles. References use the flat <tag> in both. (Nested a::b::Foo -> nested blocks.) */
        size_t nssep = L.is_class ? L.qual_name.rfind("::") : std::string::npos;
        if (nssep != std::string::npos) {
            std::string nspath = L.qual_name.substr(0, nssep);   /* "game" or "a::b" */
            std::string shortid = sani(L.qual_name.substr(nssep + 2));   /* "Entity" / "Pool_int_" */
            std::string opens, closes, qual; size_t st = 0;
            while (st <= nspath.size()) {
                size_t e2 = nspath.find("::", st);
                std::string comp = nspath.substr(st, e2 == std::string::npos ? std::string::npos : e2 - st);
                if (!comp.empty()) { opens += "namespace " + comp + " { "; closes = "} " + closes; qual += comp + "::"; }
                if (e2 == std::string::npos) break;
                st = e2 + 2;
            }
            s += "#ifdef __cplusplus\n" + opens + "\n#pragma pack(push, 1)\n" + kw + " " + shortid +
                 " {\n" + body + "};\n#pragma pack(pop)\n" + closes + "\ntypedef " + qual + shortid +
                 " " + L.tag + ";\n#else\n" + flat() + "#endif\n";
        } else {
            s += flat();
        }
        if (!guard.empty()) s += "#endif\n";
        return s;
    }
    /* Member name for a recovered struct field: an RTTI class's field_0 IS its vtable pointer
     * (see struct_typedef_str), so it prints `__vftable`; every other field is `field_<hex>`. */
    std::string fld(const ParamStruct& L, int64_t off) {
        if (L.is_class && off == 0) return "__vftable";
        /* before the shared_typedef arm: std::string sets shared_typedef to guard its one
         * definition per TU, and that arm would otherwise rename _Bx to a Vec's `x`. */
        if (L.is_stdstring) {     /* std::string -> MSVC _Bx/_Mysize/_Myres */
            switch (off) { case 0: return "_Bx"; case 0x10: return "_Mysize"; case 0x18: return "_Myres"; }
        }
        /* BEFORE the shared_typedef branch: a vector now SETS shared_typedef (to get the
         * one-definition-per-TU guard, exactly like std_string), and that branch's Vec2/3/4
         * x/y/z/w mapping would otherwise rename _Myfirst to `x`. */
        if (L.is_vector) {        /* std::vector -> MSVC _Myfirst/_Mylast/_Myend */
            switch (off) { case 0: return "_Myfirst"; case 8: return "_Mylast"; case 16: return "_Myend"; }
        }
        if (L.shared_typedef) {   /* Vec2/3/4 -> x/y/z/w */
            switch (off) { case 0: return "x"; case 4: return "y"; case 8: return "z"; case 12: return "w"; }
        }
        return "field_" + hex(off).substr(2);
    }
    /* Recognize an MSVC std::vector: the `_Mylast - _Myfirst` begin/end pointer
     * difference (its .size() numerator) over a recovered struct's fields at
     * offsets 8 and 0. That exact range subtraction is a high-precision STL
     * signature — name the fields _Myfirst/_Mylast/_Myend and tag the struct so it
     * reads as a vector, not an anonymous pointer bag. DS_NO_STLVEC. */
    void detect_stl_vectors() {
        if (std::getenv("DS_NO_STLVEC")) return;
        std::set<std::string> vecs;
        /* An MSVC std::vector is EXACTLY three 8-byte pointers {_Myfirst,_Mylast,_Myend}
         * (0x18 bytes). The begin/end pair at 0/8 alone is too weak: a serialization
         * buffer with {char* begin; char* end; int32 remaining; int32 flags; int32 idx}
         * shares the `end - begin` subtraction but its 3rd slot is a SCALAR COUNTER, not a
         * capacity pointer. Reject when offset 0x10 is present and NOT 8 bytes, or when any
         * field lands at 0x14 (which can only exist if 0x10 is a 4-byte scalar, never a
         * pointer). Absent 3rd field (a range-only vector) still passes. */
        auto vec_shape_ok = [&](const std::string& p) -> bool {
            if (!param_structs.count(p)) return false;
            const ParamStruct& L = param_structs[p];
            if (!(L.fw.count(0) && L.fw.at(0) == 8 && L.fw.count(8) && L.fw.at(8) == 8)) return false;
            if (L.fw.count(16) && L.fw.at(16) != 8) return false;
            if (L.fw.count(20)) return false;
            return true;
        };
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Binary && e->op == "-" && e->a && e->b &&
                e->a->kind == EK::Mem && e->b->kind == EK::Mem) {
                std::string pa, pb; int64_t oa = 0, ob = 0;
                if (struct_base_offset(e->a->a, pa, oa) && oa == 8 &&
                    struct_base_offset(e->b->a, pb, ob) && ob == 0 &&
                    pa == pb && vec_shape_ok(pa))
                    vecs.insert(pa);
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }

        /* SECOND SIGNATURE — the begin/end ITERATION walk. A vector consumed ONLY as a
         * range (`for (x : v)`, or an explicit begin()/end() loop) never computes .size(),
         * so the subtraction above never appears: _qa/vectest/rangefor.dll's rf_iter/rf_sum
         * are exactly that shape and left the struct an anonymous `{int64_t field_0;
         * int64_t field_8;}` pointer bag.
         * The LAYOUT is far too weak to key on — any two-qword struct matches it — so the
         * signature is the WALK: a var loaded from field_0 that is later compared against
         * field_8 of the SAME struct. A begin/end range is the only thing that does that;
         * an unrelated pointer pair is never cross-compared this way. Both halves are
         * required, exactly as the std::string detector below demands layout AND the SSO
         * discriminator. */
        {
            /* var -> the struct whose field_0 it was loaded from */
            std::map<std::string, std::string> begin_of;
            auto strip = [](ExprP o) { while (o && o->kind == EK::Cast && o->a) o = o->a; return o; };
            auto field_of = [&](const ExprP& e, int64_t want, std::string& p) -> bool {
                ExprP m = strip(e);
                if (!m || m->kind != EK::Mem) return false;
                int64_t off = 0;
                return struct_base_offset(m->a, p, off) && off == want && param_structs.count(p);
            };
            for (auto& b : blocks)
                for (auto& s : b.stmts) {
                    if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
                    std::string p;
                    if (field_of(s.rhs, 0, p) && vec_shape_ok(p)) begin_of[s.lhs->name] = p;
                }
            std::function<void(const ExprP&)> scan_cmp = [&](const ExprP& e) {
                if (!e) return;
                if (e->kind == EK::Binary && (e->op == "==" || e->op == "!=") && e->a && e->b) {
                    for (int i = 0; i < 2; ++i) {
                        ExprP v = strip(i ? e->b : e->a), k = i ? e->a : e->b;
                        std::string p;
                        if (v && v->kind == EK::Var && field_of(k, 8, p) &&
                            begin_of.count(v->name) && begin_of[v->name] == p)
                            vecs.insert(p);
                    }
                }
                scan_cmp(e->a); scan_cmp(e->b); scan_cmp(e->c);
                for (auto& ar : e->args) scan_cmp(ar);
            };
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { scan_cmp(s.lhs); scan_cmp(s.rhs); }
                scan_cmp(b.cond); scan_cmp(b.ret_value); scan_cmp(b.ret_raw);
                scan_cmp(b.switch_var); scan_cmp(b.tail_call);
            }
        }
        /* NAME THE TYPE, don't leave it an anonymous per-function bag.
         * The fields were already recovered as _Myfirst/_Mylast/_Myend, but the TYPE still
         * rendered `struct s_rf_iter_a1` — so every function that touched a vector invented
         * its own name for the same std::vector, and a signature said nothing:
         *     int32_t rf_sum(struct s_rf_sum_a1* a1)      <- what IS that?
         *     int32_t rf_sum(struct std_vector* a1)       <- a vector, in the signature
         * This is exactly what detect_stl_strings already does for std::string (tag
         * "std_string" + shared_typedef), so vectors now match that convention rather than
         * having a second one.
         *
         * NOT literally `std::vector<int>`: the dumped units are gated by compiling all 1497
         * of them with cl /TC, and that oracle is what caught the ymm store, both bool bugs
         * and milestone 24's six silent bugs. `std::vector<int>` is not C. The struct already
         * carries a "std::vector" banner comment above its definition, so the reader gets the
         * real name anyway -- see struct_comment.
         *
         * shared_typedef makes the definition __DS_TY_std_vector-guarded, so the ONE
         * definition is emitted once per TU even when several params are vectors. */
        for (auto& p : vecs) {
            ParamStruct& L = param_structs[p];
            L.is_vector = true;
            L.tag = "std_vector";       /* read at RENDER time, so retagging after mktag is safe */
            L.shared_typedef = true;
        }
    }
    /* Recognize an MSVC std::string: _Bx{char _Buf[16]; char* _Ptr}, _Mysize, _Myres. The
     * SSO discriminator IS the signature — _Myres (+0x18) compared against 15/16 is what
     * selects the inline buffer over the heap pointer, and nothing else lays out a 32-byte
     * 3-qword struct and then tests that one field against exactly that constant. The
     * layout alone is far too weak (any 3-pointer bag matches), so BOTH must hold.
     * Requires the accessors to be inlined into the caller (/O1 and up): at /Od the compare
     * lives in _Large_string_engaged and the load in _Myptr, and this scans one function.
     * DS_NO_STLSTR. */
    void detect_stl_strings() {
        if (std::getenv("DS_NO_STLSTR")) return;
        /* the canonical layout, exactly: qwords at 0 / 0x10 / 0x18 and nothing else. _Bx's
         * trailing 8 bytes read as padding because the union's tail is never loaded. */
        auto layout_ok = [&](const ParamStruct& L) {
            if (L.is_class || L.is_vector || L.shared_typedef) return false;
            if (L.fw.size() != 3) return false;
            for (int64_t o : {(int64_t)0, (int64_t)0x10, (int64_t)0x18}) {
                auto it = L.fw.find(o);
                if (it == L.fw.end() || it->second != 8) return false;
                /* a float at any of these is proof this is some other 32-byte struct */
                if (L.ff.count(o) && L.ff.at(o)) return false;
            }
            return true;
        };
        std::set<std::string> strs;
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Binary && e->a && e->b &&
                (e->op == "<=" || e->op == "<" || e->op == ">" || e->op == ">=" ||
                 e->op == "==" || e->op == "!=")) {
                /* the compare renders as `(uint64_t)(a1->field_18) <= 0xf` — the widening
                 * cast sits between the Binary and the Mem, so strip casts on both sides. */
                auto strip = [](ExprP o) { while (o && o->kind == EK::Cast) o = o->a; return o; };
                ExprP l = strip(e->a), r = strip(e->b);
                for (int i = 0; i < 2; i++) {
                    ExprP m = i ? r : l, k = i ? l : r;
                    if (!m || !k || m->kind != EK::Mem || k->kind != EK::Const) continue;
                    if (k->cval != 0xf && k->cval != 0x10) continue;
                    std::string p; int64_t off = 0;
                    if (!struct_base_offset(m->a, p, off) || off != 0x18) continue;
                    if (param_structs.count(p) && layout_ok(param_structs[p])) strs.insert(p);
                }
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }
        for (auto& p : strs) {
            ParamStruct& L = param_structs[p];
            L.is_stdstring = true;
            L.tag = "std_string";        /* read at RENDER time, so retagging after mktag is safe */
            L.shared_typedef = true;     /* -> __DS_TY_std_string guards the one definition per TU */
        }
    }

    bool used_opnew = false;                    /* an operator_new call was recovered -> emit its proto */
    std::set<std::string> imported_data;        /* data imports referenced (std::cout/cin) -> extern decls */
    std::set<std::string> referenced_vtables;   /* <Class>__vftable symbols referenced -> extern decls */
    /* OPERATOR NEW recovery: a function whose result is used as the object that a constructor
     * stores a known vtable into (`obj = fun_X(size); obj->__vftable = &<vtable>`) IS an allocator
     * (MSVC `operator new` / a pool allocator). Rename every such callee to `operator_new` and give
     * it the honest `void* operator_new(size_t)` prototype instead of `long long fun_X()`. Runs after
     * recover_struct_layouts (needs class_for_vtable + the recovered field_0 store). Gated DS_NO_OPNEW. */
