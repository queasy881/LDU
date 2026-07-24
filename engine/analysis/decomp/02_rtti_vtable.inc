/* 02_rtti_vtable.inc -- RTTI vtable lookup, virtual-call resolution, class naming
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    std::string class_for_vtable(uint64_t addr, bool* is_struct = nullptr) {
        if (!e) return "";
        static const std::string sufc = "__vftable", sufs = "__vfstruct";
        auto ends_with = [](const std::string& n, const std::string& suf) {
            return n.size() > suf.size() && n.compare(n.size()-suf.size(), suf.size(), suf) == 0;
        };
        for (uint64_t r : { addr, (addr >= e->base ? addr - e->base : addr) }) {
            for (size_t i = 0; i < e->symbol_len; ++i) {
                if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
                std::string n = e->symbols[i].name;
                /* return the RAW qualified name (keeps `::`/`<>`); the caller sani()s it for the C
                 * tag and keeps the raw form for the `namespace X { ... }` block. */
                if (ends_with(n, sufs)) { if (is_struct) *is_struct = true;
                    return n.substr(0, n.size() - sufs.size()); }
                if (ends_with(n, sufc)) { if (is_struct) *is_struct = false;
                    return n.substr(0, n.size() - sufc.size()); }
                /* `<Class>__vftable_off<N>` — a secondary vtable (MI base subobject or a
                 * VIRTUAL base). Still unambiguously this class's vtable, so it types the
                 * object exactly as the primary one does; the offset is only provenance. */
                size_t off = n.find("__vftable_off");
                if (off != std::string::npos) { if (is_struct) *is_struct = false;
                    return n.substr(0, off); }
            }
        }
        /* NOTE — an ADJUSTED SUB-VTABLE does not resolve here, deliberately.
         *
         * A class with a virtual base has several vtables: the primary one plus an
         * adjusted vtable per virtual-base subobject. An object's vfptr may target
         * any of them, and the RTTI scan seeds `<Class>__vftable` only at the one it
         * walked, so a secondary vtable misses the exact match above. std::cin hits
         * this — basic_istream derives virtually from basic_ios, and the recovered
         * class name even records the adjustment (`..._off24`).
         *
         * Resolving it by taking the NEAREST seeded vtable at or below the address
         * was tried and REVERTED: std::cin's vfptr has no seeded vtable below it that
         * belongs to it, so nearest-below silently attributed the class of whatever
         * was laid out earlier in .rdata and confidently rendered cin as a
         * `std::basic_filebuf`. Bounding the gap does not fix that — the correct
         * vtable is not seeded at ALL, so any proximity rule is guessing which class
         * a pointer belongs to. A wrong class name is worse than none: it is exactly
         * the kind of plausible lie the rest of this file refuses to emit.
         *
         * The real fix is upstream — seed a symbol for EVERY vtable a class owns
         * (walk the RTTIClassHierarchyDescriptor's base array and the vbtable rather
         * than only the vtable the COL scan landed on), after which the exact match
         * above resolves these with no proximity heuristic at all. */
        return "";
    }

    /* The DIRECT BASE of a recovered class tag, from the `<Class>__extends__<Base>` marker
     * rtti.cpp seeded off the RTTIClassHierarchyDescriptor -> BaseClassArray. "" if none.
     * Rendered as a comment on the struct header (a real `: Base` clause is C++ and the dumped
     * units compile /TC), which still gives the reader the inheritance and a catch its type. */
    std::string class_base_of(const std::string& tag) {
        if (!e || tag.empty() || std::getenv("DS_NO_RTTIBASE")) return "";
        static const char* MK = "__extends__";
        for (size_t i = 0; i < e->symbol_len; ++i) {
            const char* nm = e->symbols[i].name;
            if (!nm || !nm[0]) continue;
            std::string n = nm;
            size_t p = n.find(MK);
            if (p == std::string::npos) continue;
            if (sani(n.substr(0, p)) == tag) return n.substr(p + std::strlen(MK));
        }
        return "";
    }
    /* ALL direct bases of a class TAG, comma-joined (multiple inheritance): every
     * `<tag>__extends__<Base>` marker rtti.cpp seeded, deduped in seed order. */
    std::string class_bases_of(const std::string& tag) {
        if (!e || tag.empty() || std::getenv("DS_NO_RTTIBASE")) return "";
        struct MK { const char* mark; const char* pfx; };
        static const MK MKS[] = { {"__vextends__", "virtual "}, {"__extends__", ""} };
        std::vector<std::string> bs;
        for (size_t i = 0; i < e->symbol_len; ++i) {
            const char* nm = e->symbols[i].name;
            if (!nm || !nm[0]) continue;
            std::string n = nm;
            for (const MK& m : MKS) {
                size_t p = n.find(m.mark);
                if (p == std::string::npos || sani(n.substr(0, p)) != tag) continue;
                std::string b = m.pfx + n.substr(p + std::strlen(m.mark));
                bool dup = false; for (auto& x : bs) if (x == b) { dup = true; break; }
                if (!dup) bs.push_back(b);
                break;
            }
        }
        std::string o; for (size_t i = 0; i < bs.size(); ++i) { if (i) o += ", "; o += bs[i]; }
        return o;
    }
    /* the base class living at MI subobject offset `off` (from a `<tag>__baseoff_<off>__<Base>`
     * marker), so a this-adjustor thunk can name which base subobject it adjusts to. */
    std::string base_at_offset(const std::string& tag, int64_t off) {
        if (!e || tag.empty() || off <= 0) return "";
        char pfx[64]; std::snprintf(pfx, sizeof pfx, "__baseoff_%lld__", (long long)off);
        for (size_t i = 0; i < e->symbol_len; ++i) {
            const char* nm = e->symbols[i].name;
            if (!nm || !nm[0]) continue;
            std::string n = nm; size_t p = n.find(pfx);
            if (p == std::string::npos || sani(n.substr(0, p)) != tag) continue;
            return n.substr(p + std::strlen(pfx));
        }
        return "";
    }
    /* MI this-adjustor thunk: `sub rcx, N; jmp real_method` adjusts `this` to a base
     * subobject then tail-calls the real method. Return a header comment naming the
     * adjustment + target; "" when THIS function is not that 2-insn idiom. DS_NO_THUNKANNOT. */
    std::string thunk_annotation() {
        static const bool off = std::getenv("DS_NO_THUNKANNOT") != nullptr;
        if (off || !e || insns.size() != 2) return "";
        const Insn& a = insns[0]; const Insn& j = insns[1];
        if (!(a.id == X86_INS_SUB || a.id == X86_INS_ADD)) return "";
        if (a.x86.op_count != 2 || a.x86.operands[0].type != X86_OP_REG ||
            a.x86.operands[1].type != X86_OP_IMM) return "";
        Reg r; int w; map_reg(a.x86.operands[0].reg, r, w);
        if (r != R_RCX) return "";                              /* x64 `this` */
        if (!j.is_jmp || !j.has_branch_target || !ds_rva_is_exec(e, j.branch_target)) return "";
        std::string tn = name_for_rva(j.branch_target);
        if (tn.empty()) return "";
        int64_t adj = (a.id == X86_INS_SUB) ? -a.x86.operands[1].imm : a.x86.operands[1].imm;
        std::string tag = self_fname; size_t p;
        if ((p = tag.find("__vftbl_")) != std::string::npos) tag = tag.substr(0, p);
        if ((p = tag.find("_off")) != std::string::npos)     tag = tag.substr(0, p);
        std::string b = base_at_offset(tag, -adj);
        std::string note = b.empty() ? "" : (" (" + b + " base subobject)");
        char buf[256];
        std::snprintf(buf, sizeof buf,
            "/* this-adjustor thunk: this %s 0x%llx%s; tail-call %s */\n",
            adj < 0 ? "-=" : "+=", (unsigned long long)(adj < 0 ? -adj : adj),
            note.c_str(), tn.c_str());
        return buf;
    }
    /* class TAG (sani'd) -> its vtable RVA, by matching the `<Class>__vftable` /
     * `<Class>__vfstruct` symbol rtti.cpp seeded. Used to resolve virtual calls. */
    uint64_t vtable_rva_for_tag(const std::string& tag) {
        if (!e || tag.empty()) return 0;
        static const char* sufs[] = { "__vftable", "__vfstruct" };
        for (size_t i = 0; i < e->symbol_len; ++i) {
            const char* nm = e->symbols[i].name;
            if (!nm || !nm[0]) continue;
            std::string n = nm;
            for (const char* suf : sufs) {
                size_t sl = std::strlen(suf);
                if (n.size() > sl && n.compare(n.size() - sl, sl, suf) == 0 &&
                    sani(n.substr(0, n.size() - sl)) == tag) {
                    uint64_t r = e->symbols[i].rva;
                    return (r >= e->base) ? r - e->base : r;
                }
            }
        }
        return 0;
    }

    /* RAW qualified name + kind for a class TAG (sani'd) -- the inverse of class_for_vtable,
     * from the `<raw>__vftable`/`__vfstruct` symbol rtti.cpp seeded. Lets a recovered virtual
     * method type its `this` (a1) as its own class. */
    bool class_qual_for_tag(const std::string& tag, std::string& qual_raw, bool& is_struct_kw) {
        if (!e || tag.empty()) return false;
        static const struct { const char* suf; bool st; } S[] = {{"__vftable",false},{"__vfstruct",true}};
        for (size_t i = 0; i < e->symbol_len; ++i) {
            const char* nm = e->symbols[i].name;
            if (!nm || !nm[0]) continue;
            std::string n = nm;
            for (auto& s : S) {
                size_t sl = std::strlen(s.suf);
                if (n.size() > sl && n.compare(n.size()-sl, sl, s.suf) == 0) {
                    std::string raw = n.substr(0, n.size()-sl);
                    if (sani(raw) == tag) { qual_raw = raw; is_struct_kw = s.st; return true; }
                }
            }
        }
        return false;
    }

    /* RTTI type_info / TypeDescriptor address -> recovered class identifier. The scanner
     * seeds `<Class>__type_info` (MSVC TypeDescriptor+8 / g++ &_ZTI, the typeid operand) and
     * `<Class>__typedesc` (MSVC TypeDescriptor base, the __RTDynamicCast dst arg). Maps such an
     * address (VA or RVA) back to the class. "" if the address is not a recovered type_info. */
    std::string rtti_type_class_for_addr(uint64_t addr) {
        if (!e || addr <= 0x1000) return "";
        static const char* sufs[] = { "__type_info", "__typedesc" };
        for (uint64_t r : { addr, (addr >= e->base ? addr - e->base : addr) })
            for (size_t i = 0; i < e->symbol_len; ++i) {
                if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
                std::string n = e->symbols[i].name;
                for (const char* suf : sufs) {
                    size_t sl = std::strlen(suf);
                    if (n.size() > sl && n.compare(n.size() - sl, sl, suf) == 0)
                        return n.substr(0, n.size() - sl);
                }
            }
        return "";
    }

    /* Resolve a virtual-call target `*(long long*)(*obj + off)` to the concrete method
     * NAME via obj's recovered class vtable: obj->__vftable is `&Class__vftable`, so the
     * slot at `off` is `*(vtable_rva + off)` = the method RVA. Turns
     * `((long long(*)())(*(long long*)(*a1)))(a1)` into `Circle_area(a1)`. Gated
     * DS_NO_VCALL. Returns "" when it is not a recognizable class virtual dispatch. */
    std::string resolve_virtual_call(const ExprP& target, bool* out_recognized = nullptr,
                                     int64_t* out_off = nullptr, std::string* out_tag = nullptr) {
        if (std::getenv("DS_NO_VCALL")) return "";
        if (!target || target->kind != EK::Mem || !target->a) return "";
        ExprP inner = target->a; int64_t off = 0;
        if (inner->kind == EK::Binary && inner->op == "+" && inner->b &&
            inner->b->kind == EK::Const) { off = inner->b->cval; inner = inner->a; }
        while (inner && inner->kind == EK::Cast) inner = inner->a;
        if (!inner || inner->kind != EK::Mem || !inner->a) return "";   /* the vtable-ptr load */
        ExprP obj = inner->a;
        while (obj && obj->kind == EK::Cast) obj = obj->a;
        if (!obj || obj->kind != EK::Var) return "";
        /* the `*(*Var + const)` vtable-dispatch shape is confirmed here (for the slot annotation) */
        if (out_recognized) *out_recognized = true;
        if (out_off) *out_off = off;
        /* Identify obj's CLASS -> its vtable. Two sound sources: */
        std::string tag;
        auto it = param_structs.find(obj->name);
        if (it != param_structs.end() && it->second.is_class) {
            tag = it->second.tag;                         /* (a) obj typed a class ptr */
        } else if (obj->name == "a1" && !self_fname.empty()) {
            /* (b) THIS function is itself a recovered virtual method `<Class>__vftbl_N`,
             * so its a1 (this) IS that class -- dispatch through <Class>'s vtable even
             * though a1 was never explicitly typed. A virtual method's receiver is its
             * own class by definition, so this is sound. Enables devirtualizing a
             * virtual call made on `this` inside another virtual method. */
            size_t p = self_fname.find("__vftbl_");
            if (p != std::string::npos && p > 0) tag = self_fname.substr(0, p);
        }
        if (tag.empty()) {
            /* (c) obj is a (possibly cast) COPY of a class-typed value -- a `Class* x =
             * make(); x->m()` local that propagate_local_class_tags threaded the class to. */
            auto ct = var_class_tag.find(obj->name);
            if (ct != var_class_tag.end()) tag = ct->second;
        }
        if (out_tag) *out_tag = tag;   /* class when known (may be "") */
        if (tag.empty()) return "";
        uint64_t vt = vtable_rva_for_tag(tag);
        if (!vt) return "";
        int64_t mrva;
        if (!read_i64(vt + (uint64_t)off, mrva)) return "";
        uint64_t mr = ((uint64_t)mrva >= e->base) ? (uint64_t)mrva - e->base : (uint64_t)mrva;
        if (!ds_rva_is_exec(e, mr)) return "";   /* the slot must point at real code */
        std::string nm = name_for_rva(mr);
        if (nm.empty()) return "";
        /* Accept an RTTI-UNNAMED slot too: turning the indirect dispatch into a direct
         * `fun_XXXX(this)` still reveals the real target (which the reader can navigate
         * to) -- exactly what IDA does. Only a NAMED method needs an extern proto; a
         * fun_/sub_ target is emitted/handled by the ordinary call machinery. */
        if (nm.rfind("sub_", 0) != 0 && nm.rfind("fun_", 0) != 0)
            virtual_callees.insert(nm);
        return nm;
    }
    std::set<std::string> virtual_callees;   /* resolved vmethod names referenced -> extern decls */
    std::map<std::string,std::string> var_class_tag;   /* local -> class tag of the value it copies */

    /* Propagate a recovered class tag along local COPY chains (`Class* x = (Class*)make();
     * y = x;`) so a virtual call on a class-typed LOCAL -- not just a param or `this` --
     * devirtualizes. Seeds from param_structs' is_class vars; fixpoint over cast-stripped
     * Var=Var copies; a var assigned two different class tags becomes ambiguous and is
     * dropped (never a wrong dispatch). vtable_rva_for_tag gate keeps it to real classes.
     * DS_NO_VCALL_LOCAL. */
    void propagate_local_class_tags() {
        if (std::getenv("DS_NO_VCALL_LOCAL")) return;
        std::set<std::string> ambig;
        auto tag_of = [&](const std::string& v) -> std::string {
            auto it = param_structs.find(v);
            if (it != param_structs.end() && it->second.is_class) return it->second.tag;
            auto ct = var_class_tag.find(v);
            return (ct != var_class_tag.end()) ? ct->second : std::string();
        };
        for (int iter = 0; iter < 4; ++iter) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            bool changed = false;
            for (auto& b : blocks) for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
                ExprP r = s.rhs; while (r && r->kind == EK::Cast) r = r->a;
                if (!r || r->kind != EK::Var) continue;
                const std::string& dst = s.lhs->name;
                if (ambig.count(dst)) continue;
                std::string tag = tag_of(r->name);
                if (tag.empty() || !vtable_rva_for_tag(tag)) continue;
                auto ex = var_class_tag.find(dst);
                if (ex == var_class_tag.end())      { var_class_tag[dst] = tag; changed = true; }
                else if (ex->second != tag)         { var_class_tag.erase(ex); ambig.insert(dst); changed = true; }
            }
            if (!changed) break;
        }
    }

    /* A `xrefs: called by NAME (N sites)` header comment for THIS function, built
     * from the whole-program call graph (e->refs, populated once by build_xrefs).
     * Each ref's `from` is a CALL-site rva; map it to its containing function start
     * (funcs sorted by rva), tally sites per caller, and render the top callers by
     * count. Empty when f has no internal callers (a leaf/export) or xrefs weren't
     * built. Comment-only — never affects emitted C. Gated by DS_NO_XREFCOMMENT. */
    std::string build_xref_comment() {
        static const bool off = std::getenv("DS_NO_XREFCOMMENT") != nullptr;
        if (off || !e || !f || e->ref_len == 0) return "";
        auto owner_of = [&](uint64_t rva) -> uint64_t {
            if (e->func_len == 0) return rva;
            size_t lo = 0, hi = e->func_len;
            while (lo < hi) { size_t mid = lo + ((hi - lo) >> 1);
                if (e->funcs[mid].rva <= rva) lo = mid + 1; else hi = mid; }
            if (lo == 0) return rva;
            const ds_func& fn = e->funcs[lo - 1];
            uint64_t next = (lo < e->func_len) ? e->funcs[lo].rva : UINT64_MAX;
            if (rva >= fn.rva && (rva < fn.rva + fn.size || (fn.size == 0 && rva < next)))
                return fn.rva;
            return rva;
        };
        std::map<uint64_t, int> callers;   /* caller-func start -> call-site count */
        for (size_t i = 0; i < e->ref_len; ++i) {
            if (e->refs[i].kind != DS_XREF_CALL || e->refs[i].to != f->rva) continue;
            uint64_t owner = owner_of(e->refs[i].from);
            if (owner == f->rva) continue;   /* self-recursion is not an xref */
            callers[owner]++;
        }
        if (callers.empty()) return "";
        std::vector<std::pair<std::string, int>> v;
        for (auto& kv : callers) v.push_back({ name_for_rva(kv.first), kv.second });
        std::sort(v.begin(), v.end(), [](const std::pair<std::string, int>& a,
                                         const std::pair<std::string, int>& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });
        std::string c = "/* xrefs: called by ";
        const size_t cap = 8;
        for (size_t i = 0; i < v.size() && i < cap; ++i) {
            if (i) c += ", ";
            c += v[i].first + " (" + std::to_string(v[i].second) +
                 (v[i].second == 1 ? " site)" : " sites)");
        }
        if (v.size() > cap) c += ", +" + std::to_string(v.size() - cap) + " more";
        c += " */\n";
        return c;
    }

    /* A `confidence: HIGH|MEDIUM|LOW` header telling the reader how much of THIS
     * function the engine actually recovered, from signals it already has — no new
     * analysis, no semantic change. The honest counterweight to output that other-
     * wise reads uniformly authoritative: unmodeled ops, phantom live-ins, residual
     * gotos, a state-machine fallback and EH funclets each mean some of the original
     * behaviour is approximated or missing. HIGH only when NONE of them fired.
     * Deliberately NOT reported: whether the signature came from the sigtab or a
     * guess. build_sig_table assigns tab[f.rva] on every path incl. its bail-outs,
     * so the answer is "sigtab" for 100% of functions, and FuncSig carries no
     * provenance bit — the sigtab IS the guess. Emitting it would be a confident
     * lie about provenance, the exact failure this header exists to prevent.
     * Gated by DS_NO_CONFIDENCE. */
    std::string build_confidence_comment(const std::string& body,
                                         const std::set<std::string>& referenced) {
        static const bool off = std::getenv("DS_NO_CONFIDENCE") != nullptr;
        if (off || !f) return "";

        /* Only ops SURVIVING into the emitted text count: DSE/CSE may have dropped
         * the intrinsic entirely, and a reader cannot distrust what they cannot see. */
        std::vector<std::pair<std::string,int>> op;
        int n_opaque = 0;
        for (auto& kv : opaque_ops) {
            if (body.find(kv.first + "(") == std::string::npos) continue;
            /* An intrinsic we emit a real DEFINITION for is modelled, not opaque —
             * the reader can see exactly what it computes. Counting it as unmodelled
             * would understate confidence for something fully specified. */
            if (is_modelled_intrinsic(kv.first)) continue;
            op.push_back({ kv.first, kv.second });
            n_opaque += kv.second;
        }
        /* DS_OPAQUE_CENSUS: machine-readable tally of the GENUINELY unmodelled ops,
         * taken from the opaque_ops counter rather than by grepping the text. The
         * distinction matters: most `__`-prefixed names in the output
         * (__readgsqword/__umulh/__min/...) are exactly modelled and have real
         * construction sites, so a text scan brands them unmodelled when they are
         * not. Aggregate across a whole binary to rank what is worth modelling. */
        if (std::getenv("DS_OPAQUE_CENSUS"))
            for (auto& kv : op)
                fprintf(stderr, "OPAQUE %s %d\n", kv.first.c_str(), kv.second);
        std::sort(op.begin(), op.end(), [](const std::pair<std::string,int>& a,
                                           const std::pair<std::string,int>& b) {
            if (a.second != b.second) return a.second > b.second;
            return a.first < b.first;
        });

        /* Phantom live-ins: values read before any definition, rendered as the
         * in_<REG> placeholder. Mirrors the `uord` declaration pass exactly —
         * unknown_reg_name is ERASED on promotion to a param, while the
         * unknown_value_count firing counter never decrements and over-reports. */
        int n_phantom = 0;
        for (auto& kv : unknown_reg_name)
            if (referenced.count(kv.second)) ++n_phantom;

        /* Count REAL goto STATEMENTS: `goto <label>;`. A bare "goto " substring also matches
         * any COMMENT that says the word — the one-goto duplication note does — and the
         * header then reports "2 residual gotos" for a function containing one. The header
         * exists to make the output trustworthy, so it does not get to be sloppy about its
         * own arithmetic. (The same unanchored pattern fooled a hand grep during this work
         * and inflated a whole-binary count by 69.) */
        int n_goto = 0;
        for (size_t gp = 0; (gp = body.find("goto ", gp)) != std::string::npos; gp += 5) {
            size_t q = gp + 5;
            while (q < body.size() && (isalnum((unsigned char)body[q]) || body[q] == '_')) ++q;
            if (q > gp + 5 && q < body.size() && body[q] == ';') ++n_goto;
        }

        bool sm = body.find("switch (__state") != std::string::npos ||
                  body.find("switch(__state")  != std::string::npos;
        bool eh = petab && petab->eh.count(f->rva) != 0;

        if (!n_opaque && !n_phantom && !n_goto && !sm && !eh)
            return "/* confidence: HIGH */\n";

        std::vector<std::string> why;
        if (n_opaque) {
            std::string s = std::to_string(n_opaque) +
                            (n_opaque == 1 ? " unmodeled op (" : " unmodeled ops (");
            const size_t cap = 8;
            for (size_t i = 0; i < op.size() && i < cap; ++i) {
                if (i) s += ", ";
                s += op[i].first;
            }
            if (op.size() > cap) s += ", +" + std::to_string(op.size() - cap) + " more";
            why.push_back(s + ")");
        }
        if (n_phantom) why.push_back(std::to_string(n_phantom) +
                                     (n_phantom == 1 ? " phantom live-in" : " phantom live-ins"));
        if (n_goto)    why.push_back(std::to_string(n_goto) +
                                     (n_goto == 1 ? " residual goto" : " residual gotos"));
        if (sm)        why.push_back("state-machine fallback");
        if (eh)        why.push_back("EH funclets");

        /* An unstructured body (state machine, or gotos/unknowns past a couple) is
         * where the C diverges most from the original; a lone stray op is not. */
        const char* tier = (sm || n_goto > 2 || (n_opaque + n_phantom) > 2) ? "LOW" : "MEDIUM";
        std::string c = std::string("/* confidence: ") + tier + " - ";
        for (size_t i = 0; i < why.size(); ++i) { if (i) c += ", "; c += why[i]; }
        return c + " */\n";
    }

    /* =================================================================== */
    /*  1. disassemble                                                      */
    /* =================================================================== */
    bool disassemble() {
        if (!e || !f) return false;
        if (f->rva >= e->image_size) return false;
        uint64_t avail = e->image_size - f->rva;
        size_t n = (size_t)((f->size && f->size <= avail) ? f->size : avail);
        if (n == 0) return false;
        if (n > 0x40000) n = 0x40000;   /* cap: never hang on a huge func */

        cs_mode mode = (e->arch == DS_ARCH_X64) ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
            return false;
        handle_ok = true;
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

        cs_insn* ci = nullptr;
        size_t count = cs_disasm(handle, e->image + f->rva, n, f->rva, 0, &ci);
        if (count == 0) { if (ci) cs_free(ci, count); return false; }
        if (count > 20000) count = 20000;

        for (size_t i = 0; i < count; ++i) {
            cs_insn& c = ci[i];
            Insn in;
            in.addr = c.address;
            in.size = c.size;
            in.id   = c.id;
            in.mnem = c.mnemonic;
            in.ops  = c.op_str;
            if (c.detail) in.x86 = c.detail->x86;
            else std::memset(&in.x86, 0, sizeof(in.x86));

            in.is_call = (c.id == X86_INS_CALL);
            in.is_ret  = (c.id == X86_INS_RET || c.id == X86_INS_RETF ||
                          c.id == X86_INS_RETFQ);
            in.is_jmp  = (c.id == X86_INS_JMP);
            in.is_jcc  = (jcc_of(c.id) != CC::NONE);

            if ((in.is_jmp || in.is_jcc || in.is_call) && c.detail) {
                cs_x86* x = &c.detail->x86;
                for (int k = 0; k < x->op_count; ++k) {
                    if (x->operands[k].type == X86_OP_IMM) {
                        in.branch_target = (uint64_t)x->operands[k].imm;
                        in.has_branch_target = true;
                        break;
                    }
                }
            }
            idx_by_addr[in.addr] = (int)insns.size();
            insns.push_back(std::move(in));
        }
        cs_free(ci, count);
        return !insns.empty();
    }

    /* =================================================================== */
    /*  Jump-table recovery (must run before CFG edge building)             */
    /* =================================================================== */

    struct JumpTable {
        bool valid = false;
        ExprP index;                 /* the recovered index expression */
        Reg index_reg = R_NONE;      /* the table-index register (in the dispatch
                                      * block), resolved to its real value post-exec */
        uint64_t index_load_addr = 0;/* address of the `mov reg,[base+index*4+disp]`
                                      * table load — the index reg holds the real
                                      * selector value HERE (it is reused as the jump
                                      * target right after), so snapshot it at this
                                      * exact insn, not at any indexed access. */
        std::vector<uint64_t> targets; /* case rva per index 0..n-1 */
        uint64_t default_target = 0; /* 2-level tables: the default-arm rva (most
                                      * index-table slots point here); such case
                                      * slots are emitted as `default:`, not cases */
    };

    /* Recognise the MSVC /Od dispatch tail:
     *     movsxd reg, [idxslot]            ; or mov reg32,[idxslot]
     *     lea    base, [rip + d]           ; base = lea target rva
     *     mov    eax, [base*1 + reg*4 + T] ; (capstone: base=basereg,index=reg,scale4,disp=T)
     *     add    rax, base
     *     jmp    rax
     * The table at (lea_target_rva + T) holds n 32-bit signed entries; each case
     * target rva = lea_target_rva + entry. n is bounded by a preceding
     *     cmp idx, K ; ja default   (so n = K+1). We also cap by image bounds.
     */
    JumpTable recover_jump_table(const std::vector<int>& body_idx,
                                 int last_insn_index, int64_t& bound_hint,
                                 ExprP& idx_for_cmp) {
        JumpTable jt;
        /* find the indirect jmp reg */
        const Insn& jmpi = insns[last_insn_index];
        if (!jmpi.is_jmp || jmpi.x86.op_count < 1) return jt;
        if (jmpi.x86.operands[0].type != X86_OP_REG) return jt;
        Reg jreg; int jw; map_reg(jmpi.x86.operands[0].reg, jreg, jw);
        if (jreg == R_NONE) return jt;

        /* scan backwards within the block for the pattern */
        int n = (int)body_idx.size();
        if (n < 3) return jt;
        /* position of jmp in body */
        int jpos = -1;
        for (int i = 0; i < n; ++i) if (body_idx[i] == last_insn_index) { jpos = i; break; }
        if (jpos < 0) return jt;

        Reg base_reg = R_NONE; int64_t lea_target = -1;
        Reg index_reg = R_NONE; int64_t table_disp = 0; bool table_found = false;
        int scale = 4; uint64_t index_load_addr = 0;

        /* expected: add jreg, base_reg ; before it the mov that loads jreg from table.
         * Scan the WHOLE dispatch block backward (not just 8 insns): MSVC /O2 schedules
         * the operand-decode ALU ops BETWEEN the table load and the `jmp`, so the table
         * load can be 10+ instructions before the jmp (big_vm's 41-way opcode switch put
         * 7 shr/and ops in between → the 8-insn window missed it → mis-lowered as a
         * tail-call, severing the interpreter loop). First-wins (closest to jmp) guards
         * keep every existing recovery identical. */
        for (int i = jpos - 1; i >= 0; --i) {
            const Insn& in = insns[body_idx[i]];
            const cs_x86& x = in.x86;
            if (in.id == X86_INS_ADD && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_REG) {
                Reg d, s; int wd, ws;
                map_reg(x.operands[0].reg, d, wd); map_reg(x.operands[1].reg, s, ws);
                if (d == jreg && base_reg == R_NONE) base_reg = s;
                continue;
            }
            if (!table_found &&
                (in.id == X86_INS_MOV || in.id == X86_INS_MOVSXD) &&
                x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_MEM) {
                Reg d; int wd; map_reg(x.operands[0].reg, d, wd);
                if (d != jreg) continue;
                const x86_op_mem& m = x.operands[1].mem;
                /* the table load is the indexed form [base + index*4 + disp] */
                if (m.index == X86_REG_INVALID) continue;
                Reg mb = R_NONE, mi = R_NONE; int t;
                if (m.base != X86_REG_INVALID) map_reg(m.base, mb, t);
                map_reg(m.index, mi, t);
                table_disp = m.disp; scale = m.scale ? m.scale : 1;
                index_reg = mi; table_found = true;
                index_load_addr = in.addr;   /* snapshot the selector reg HERE */
                if (mb != R_NONE && base_reg == R_NONE) base_reg = mb;
                continue;
            }
            if (in.id == X86_INS_LEA && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_MEM) {
                Reg d; int wd; map_reg(x.operands[0].reg, d, wd);
                const x86_op_mem& m = x.operands[1].mem;
                if (m.base == X86_REG_RIP) {
                    uint64_t t = in.addr + in.size + (uint64_t)m.disp;
                    if (d == base_reg) { if (lea_target < 0) lea_target = (int64_t)t; }
                    else if (base_reg == R_NONE && (jpos - i) <= 8) {
                        /* "the base IS this lea'd reg" heuristic — only trust it near the
                         * jmp; distant base leas are handled by the whole-fn backfill below */
                        base_reg = d; lea_target = (int64_t)t;
                    }
                }
                continue;
            }
        }
        /* The base register (the image/section base the table is relative to) is
         * commonly loaded ONCE in the prologue — `lea rdx, [rip - func_rva]` gives
         * RVA 0 — far from the dispatch jmp. The 8-instruction local window misses
         * it, so a whole switch (0x57760's 16-way InputText cursor dispatcher) was
         * mis-recovered as an indirect TAIL CALL, disconnecting every case block
         * and dropping the object pointer to `(char*)(0)`. Search the whole
         * function (nearest definition before the jmp) for base_reg's lea. */
        if (table_found && base_reg != R_NONE && lea_target < 0) {
            for (int i = last_insn_index - 1; i >= 0; --i) {
                const Insn& in = insns[i];
                const cs_x86& x = in.x86;
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
                    Reg d; int wd; map_reg(x.operands[0].reg, d, wd);
                    if (d == base_reg) {
                        if (in.id == X86_INS_LEA && x.op_count == 2 &&
                            x.operands[1].type == X86_OP_MEM &&
                            x.operands[1].mem.base == X86_REG_RIP) {
                            lea_target = (int64_t)(in.addr + in.size +
                                         (uint64_t)x.operands[1].mem.disp);
                        }
                        break;   /* nearest def of base_reg decides */
                    }
                }
            }
        }
        if (!table_found || base_reg == R_NONE || lea_target < 0 || scale != 4)
            return jt;

        uint64_t table_rva = (uint64_t)(lea_target + table_disp);
        /* determine count bound */
        int64_t count = bound_hint;
        if (count <= 0 || count > 4096) count = 256;   /* clamp */
        /* read entries, bounded by image and by a plausible code range */
        uint64_t lo = f->rva;
        uint64_t hi = f->rva + (f->size ? f->size : 0);
        if (hi <= lo && !insns.empty()) hi = insns.back().addr + insns.back().size;
        std::vector<uint64_t> targets;
        for (int64_t i = 0; i < count; ++i) {
            int32_t entry;
            if (!read_i32(table_rva + (uint64_t)i * 4, entry)) break;
            uint64_t tgt = (uint64_t)(lea_target + entry);
            if (tgt < lo || tgt >= hi) break;       /* outside function: stop */
            if (!idx_by_addr.count(tgt)) break;     /* not an instruction start */
            targets.push_back(tgt);
        }
        if (targets.size() < 2) return jt;

        /* 2-level (sparse) table: the jump-table index is itself loaded from a
         * BYTE index table — `movzx index_reg, byte [ibase + v*1 + d]` — so the
         * jump-table position is NOT the switch value. Read the byte table and
         * EXPAND targets to one-per-real-value, so case labels are the actual
         * switch keys (parse_bool/classify_char/best_caesar_shift were labelling
         * cases by jump-table rank instead of the real char value). */
        if (index_reg != R_NONE) {
            Reg itab_base = R_NONE; int64_t itab_disp = 0;
            Reg real_idx = R_NONE; bool itab_found = false;
            for (int i = jpos - 1; i >= 0; --i) {
                const Insn& in = insns[body_idx[i]];
                const cs_x86& x = in.x86;
                if ((in.id==X86_INS_MOVZX||in.id==X86_INS_MOVSX||in.id==X86_INS_MOV) &&
                    x.op_count==2 && x.operands[0].type==X86_OP_REG &&
                    x.operands[1].type==X86_OP_MEM) {
                    Reg d; int dw; map_reg(x.operands[0].reg, d, dw);
                    if (d != index_reg) continue;
                    const x86_op_mem& m = x.operands[1].mem;
                    if (m.index == X86_REG_INVALID) break;        /* non-indexed def: stop */
                    if ((m.scale ? m.scale : 1) != 1) continue;   /* the scale-4 jump-table load itself — skip past it to the byte index table */
                    Reg mb=R_NONE, mi=R_NONE; int t;
                    if (m.base != X86_REG_INVALID) map_reg(m.base, mb, t);
                    map_reg(m.index, mi, t);
                    itab_base = mb; itab_disp = m.disp; real_idx = mi; itab_found = true;
                    break;
                }
            }
            int64_t itab_lea = -1;
            if (itab_found) {
                for (int i = jpos - 1; i >= 0; --i) {
                    const Insn& in = insns[body_idx[i]];
                    const cs_x86& x = in.x86;
                    if (in.id==X86_INS_LEA && x.op_count==2 &&
                        x.operands[0].type==X86_OP_REG && x.operands[1].type==X86_OP_MEM) {
                        Reg d; int dw; map_reg(x.operands[0].reg, d, dw);
                        const x86_op_mem& m = x.operands[1].mem;
                        if (d==itab_base && m.base==X86_REG_RIP)
                            itab_lea = (int64_t)(in.addr + in.size + (uint64_t)m.disp);
                    }
                }
            }
            if (itab_lea >= 0) {
                uint64_t itab_rva = (uint64_t)(itab_lea + itab_disp);
                std::vector<uint64_t> expanded;
                int64_t cnt = bound_hint; if (cnt <= 0 || cnt > 4096) cnt = 256;
                std::map<uint64_t,int> freq;
                for (int64_t v = 0; v < cnt; ++v) {
                    uint8_t ix;
                    if (!read_u8(itab_rva + (uint64_t)v, ix)) break;
                    if ((size_t)ix >= targets.size()) break;
                    expanded.push_back(targets[ix]);
                    freq[targets[ix]]++;
                }
                if (expanded.size() >= 2) {
                    uint64_t deflt = 0; int best = -1;
                    for (auto& kv : freq) if (kv.second > best) { best = kv.second; deflt = kv.first; }
                    targets = expanded;
                    jt.default_target = deflt;
                    index_reg = (real_idx != R_NONE) ? real_idx : index_reg;
                    idx_for_cmp = nullptr;   /* re-trace from the real index reg */
                }
            }
        }

        jt.valid = true;
        jt.targets = targets;
        /* Recover the index expression. Prefer the cmp-derived index; otherwise
         * trace index_reg back to the slot it was loaded from in this block. */
        ExprP idx = idx_for_cmp;
        if (!idx && index_reg != R_NONE) {
            Reg trace = index_reg;
            for (int i = jpos - 1; i >= 0; --i) {
                const Insn& in = insns[body_idx[i]];
                const cs_x86& x = in.x86;
                if ((in.id == X86_INS_MOV || in.id == X86_INS_MOVSXD ||
                     in.id == X86_INS_MOVZX || in.id == X86_INS_MOVSX) &&
                    x.op_count == 2 && x.operands[0].type == X86_OP_REG) {
                    Reg d; int dw; map_reg(x.operands[0].reg, d, dw);
                    if (d != trace) continue;
                    if (x.operands[1].type == X86_OP_MEM) {
                        const x86_op_mem& mm = x.operands[1].mem;
                        /* skip the table load itself (indexed mem) */
                        if (mm.index != X86_REG_INVALID) continue;
                        idx = symbolic_operand_static(x.operands[1]);
                        break;
                    } else if (x.operands[1].type == X86_OP_REG) {
                        Reg s; int sw; map_reg(x.operands[1].reg, s, sw);
                        trace = s; continue;
                    } else break;
                }
            }
        }
        jt.index = idx;
        jt.index_reg = index_reg;   /* dispatch-block register, resolved post-exec */
        jt.index_load_addr = index_load_addr;
        return jt;
    }

    /* =================================================================== */
    /*  2. CFG                                                              */
    /* =================================================================== */

    std::map<int, JumpTable> block_jt;   /* block id -> recovered jump table */

    void build_cfg() {
        uint64_t lo = f->rva;
        uint64_t hi = f->rva + (f->size ? f->size : 0);
        if (hi <= lo && !insns.empty())
            hi = insns.back().addr + insns.back().size;

        /* First pass: find leaders from direct branches + collect jump tables. */
        std::set<uint64_t> leaders;
        leaders.insert(f->rva);
        for (size_t i = 0; i < insns.size(); ++i) {
            const Insn& in = insns[i];
            bool term = in.is_jmp || in.is_jcc || in.is_ret;
            if ((in.is_jcc || in.is_jmp) && in.has_branch_target &&
                in.branch_target >= lo && in.branch_target < hi)
                leaders.insert(in.branch_target);
            if (term && i + 1 < insns.size())
                leaders.insert(insns[i + 1].addr);
        }

        /* Provisional blocks to find jump-table dispatch tails. We need block
         * groupings; build a quick provisional leader list, locate switch
         * dispatch blocks, add their case targets as leaders, then rebuild. */
        auto build_blocks_from = [&](std::set<uint64_t>& leadset) {
            blocks.clear(); block_by_addr.clear();
            std::vector<uint64_t> lead;
            for (uint64_t L : leadset) if (idx_by_addr.count(L)) lead.push_back(L);
            std::sort(lead.begin(), lead.end());
            for (size_t bi = 0; bi < lead.size(); ++bi) {
                Block b; b.addr = lead[bi]; b.id = (int)bi;
                block_by_addr[b.addr] = b.id; blocks.push_back(b);
            }
            for (size_t bi = 0; bi < blocks.size(); ++bi) {
                uint64_t start = blocks[bi].addr;
                uint64_t end = (bi + 1 < blocks.size()) ? blocks[bi + 1].addr : hi;
                if (!idx_by_addr.count(start)) continue;
                int si = idx_by_addr[start];
                for (int j = si; j < (int)insns.size(); ++j) {
                    if (insns[j].addr < start) continue;
                    if (insns[j].addr >= end) break;
                    blocks[bi].insn_idx.push_back(j);
                }
            }
        };

        build_blocks_from(leaders);

        /* Detect jump tables: blocks ending in an indirect jmp reg. */
        for (auto& b : blocks) {
            if (b.insn_idx.empty()) continue;
            const Insn& last = insns[b.insn_idx.back()];
            if (!last.is_jmp || last.has_branch_target) continue;
            if (last.x86.op_count < 1 || last.x86.operands[0].type != X86_OP_REG)
                continue;
            /* find a preceding `cmp idx, K ; ja` to bound the table */
            int64_t bound = 0;
            ExprP idxexpr = nullptr;
            for (int i = (int)b.insn_idx.size() - 1; i >= 0; --i) {
                const Insn& in = insns[b.insn_idx[i]];
                if (in.id == X86_INS_CMP && in.x86.op_count == 2 &&
                    in.x86.operands[1].type == X86_OP_IMM) {
                    bound = in.x86.operands[1].imm + 1;
                    idxexpr = symbolic_operand_static(in.x86.operands[0]);
                    break;
                }
            }
            JumpTable jt = recover_jump_table(b.insn_idx, b.insn_idx.back(),
                                              bound, idxexpr);
            if (jt.valid) {
                block_jt[b.id] = jt;
                for (uint64_t t : jt.targets) leaders.insert(t);
            }
        }

        /* Rebuild blocks now that case targets are leaders. */
        build_blocks_from(leaders);

        /* edges */
        for (size_t bi = 0; bi < blocks.size(); ++bi) {
            Block& b = blocks[bi];
            if (b.insn_idx.empty()) {
                if (bi + 1 < blocks.size()) b.fall = (int)bi + 1;
                continue;
            }
            const Insn& last = insns[b.insn_idx.back()];
            uint64_t next_addr = last.addr + last.size;

            /* recovered switch? (re-detect; block ids changed on rebuild) */
            bool isjt = false;
            if (last.is_jmp && !last.has_branch_target &&
                last.x86.op_count >= 1 && last.x86.operands[0].type == X86_OP_REG) {
                int64_t bound = 0; ExprP idxexpr = nullptr; Reg cmp_reg = R_NONE;
                for (int i = (int)b.insn_idx.size() - 1; i >= 0; --i) {
                    const Insn& in = insns[b.insn_idx[i]];
                    if (in.id == X86_INS_CMP && in.x86.op_count == 2 &&
                        in.x86.operands[1].type == X86_OP_IMM) {
                        bound = in.x86.operands[1].imm + 1;
                        idxexpr = symbolic_operand_static(in.x86.operands[0]);
                        if (in.x86.operands[0].type == X86_OP_REG) {
                            int cw; map_reg(in.x86.operands[0].reg, cmp_reg, cw);
                        }
                        break;
                    }
                }
                JumpTable jt = recover_jump_table(b.insn_idx, b.insn_idx.back(),
                                                  bound, idxexpr);
                if (jt.valid) {
                    isjt = true;
                    b.is_switch = true;
                    b.switch_var = jt.index;
                    /* the cmp-derived index renders statically (often `0`) because
                     * the CFG pass has no regfile; remember the dispatch register
                     * (the jump-table index reg, in THIS block — the bound-check cmp
                     * usually sits in a predecessor) so exec_block can rebind
                     * switch_var to its real dataflow value (`switch(*a1)` not
                     * `switch(0)`). Fall back to the cmp operand if no index reg. */
                    Reg sreg = (jt.index_reg != R_NONE) ? jt.index_reg : cmp_reg;
                    if (sreg != R_NONE) switch_cmp_reg[b.id] = sreg;
                    if (jt.index_load_addr) switch_index_load[b.id] = jt.index_load_addr;
                    for (uint64_t t : jt.targets) {
                        /* a slot pointing at the 2-level default arm is NOT a case */
                        if (jt.default_target && t == jt.default_target) {
                            b.case_succ.push_back(-1);
                            continue;
                        }
                        int sid = block_by_addr.count(t) ? block_by_addr[t] : -1;
                        b.case_succ.push_back(sid);
                    }
                    if (jt.default_target && block_by_addr.count(jt.default_target))
                        b.default_succ = block_by_addr[jt.default_target];
                }
            }

            if (last.is_ret) {
                b.ends_ret = true;
            } else if (isjt) {
                b.ends_jmp = true;
                /* succ edges added below from case_succ + default */
            } else if (last.is_jmp) {
                b.ends_jmp = true;
                if (last.has_branch_target && block_by_addr.count(last.branch_target))
                    b.taken = block_by_addr[last.branch_target];
            } else if (last.is_jcc) {
                b.ends_jcc = true;
                b.cc = jcc_of(last.id);
                if (last.has_branch_target && block_by_addr.count(last.branch_target))
                    b.taken = block_by_addr[last.branch_target];
                if (block_by_addr.count(next_addr))
                    b.fall = block_by_addr[next_addr];
            } else {
                if (block_by_addr.count(next_addr))
                    b.fall = block_by_addr[next_addr];
            }
        }

        /* succ/pred */
        for (auto& b : blocks) {
            std::set<int> added;
            auto addedge = [&](int s) {
                if (s < 0 || added.count(s)) return;
                added.insert(s);
                b.succ.push_back(s);
                blocks[s].pred.push_back(b.id);
            };
            if (b.is_switch) {
                for (int s : b.case_succ) addedge(s);
                if (b.default_succ >= 0) addedge(b.default_succ);
            } else {
                if (b.taken >= 0) addedge(b.taken);
                if (b.fall >= 0) addedge(b.fall);
            }
        }

        /* Identify switch guard blocks: a block ending in an unsigned bound check
         * (`ja`/`jae`) whose fall-through is a switch-dispatch block. The taken
         * edge is the switch default. We attach the default to the switch block
         * and mark the guard so the structurer emits one clean switch. */
        for (auto& b : blocks) {
            if (!b.ends_jcc || b.taken < 0 || b.fall < 0) continue;
            if (!(b.cc == CC::A || b.cc == CC::AE || b.cc == CC::G || b.cc == CC::GE))
                continue;
            Block& fb = blocks[b.fall];
            if (!fb.is_switch) continue;
            /* only when the switch block's only forward entry is this guard */
            b.is_switch_guard = true;
            b.guard_switch_blk = b.fall;
            if (fb.default_succ < 0) {
                fb.default_succ = b.taken;
                /* add default edge */
                bool present = false;
                for (int s : fb.succ) if (s == b.taken) present = true;
                if (!present) {
                    fb.succ.push_back(b.taken);
                    blocks[b.taken].pred.push_back(fb.id);
                }
            }
        }
    }

