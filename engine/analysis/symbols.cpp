/*
 * symbols.cpp — ds_engine_resolve_symbols().
 *
 * Name each recovered function by this priority (first hit wins):
 *   (1) seeded symbol whose rva == func.rva (export / debug name).
 *   (2) entry point: func.rva == entry_rva -> "DllMain" (dll) / "start" (exe).
 *   (3) import thunk: a function whose body is essentially a single
 *       jmp [rip+disp] / call+jmp through a known IAT slot -> "j_<import>".
 *   (4) built-in FLIRT-ish signatures for a few ubiquitous MSVC stubs.
 *   (5) fallback: "fun_" + 8-hex-lowercase of the rva.
 *
 * Exports discovered as functions are named even if they weren't the priority-1
 * winner at the prologue (we match seeded symbols by rva first regardless).
 */
#include "disasm.h"
#include "engine_internal.h"

#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

#include <map>
#include <set>
#include <string>

namespace {

size_t insn_index_exact(const ds_engine* e, uint64_t rva) {
    size_t lo = 0, hi = e->insn_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->insns[mid].rva < rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo < e->insn_len && e->insns[lo].rva == rva) return lo;
    return SIZE_MAX;
}

/* seeded symbol name for an rva, or NULL */
const char* seeded_symbol(const ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].rva == rva && e->symbols[i].name[0])
            return e->symbols[i].name;
    return NULL;
}

/* import name for an IAT slot rva, or NULL */
const char* import_for_iat(const ds_engine* e, uint64_t iat_rva) {
    for (size_t i = 0; i < e->import_len; ++i)
        if (e->imports[i].iat_rva == iat_rva)
            return e->imports[i].name;
    return NULL;
}

bool mnem_is(const ds_insn* in, const char* m) {
    return std::strncmp(in->mnemonic, m, sizeof(in->mnemonic)) == 0;
}

/* If the function is a single jmp [rip+disp] (FF /4) through an IAT slot, return
 * the resolved import name, else NULL. The decoder sets ref_type=DS_REF_JMP and
 * ref_target to the IAT slot rva for `jmp [rip+disp]`. */
const char* import_thunk_name(const ds_engine* e, uint64_t fstart) {
    size_t idx = insn_index_exact(e, fstart);
    if (idx == SIZE_MAX) return NULL;
    const ds_insn* in = &e->insns[idx];
    if (!mnem_is(in, "jmp")) return NULL;
    /* the thunk dereferences an IAT slot: ref_target is that slot rva */
    if (in->ref_type != DS_REF_JMP || in->ref_target == 0) return NULL;
    const char* imp = import_for_iat(e, in->ref_target);
    if (imp) return imp;
    /* also: direct jmp to a known import target rva (rare) */
    return NULL;
}

/* tiny FLIRT-ish signature table keyed on the first opcode bytes. Returns a
 * static name or NULL. These are very common MSVC runtime stubs. */
const char* flirt_match(const ds_insn* first, const ds_engine* e, size_t idx) {
    (void)e;
    const uint8_t* b = first->bytes;
    uint8_t n = first->size;

    /* __security_check_cookie (x64):  cmp rcx, [rip+cookie]  -> 48 3B 0D ?? ?? ?? ??
       followed by jne ... ; ret. Match the leading cmp rcx,[rip]. */
    if (n >= 3 && b[0] == 0x48 && b[1] == 0x3B && b[2] == 0x0D) {
        /* confirm it's short (cmp; jne; rep ret) */
        if (idx + 1 < e->insn_len) {
            const ds_insn* nx = &e->insns[idx + 1];
            if (mnem_is(nx, "jne") || mnem_is(nx, "jnz"))
                return "__security_check_cookie";
        }
        return "__security_check_cookie";
    }
    /* x86 __security_check_cookie: 3B 0D ?? ?? ?? ?? cmp ecx,[cookie] */
    if (n >= 2 && b[0] == 0x3B && b[1] == 0x0D) {
        return "__security_check_cookie";
    }
    /* _RTC_CheckEsp:  3B EC  cmp ebp, esp ; (jne) ; ret */
    if (n >= 2 && b[0] == 0x3B && b[1] == 0xEC) {
        return "_RTC_CheckEsp";
    }
    /* __security_init_cookie often starts with: 48 83 EC 28 (sub rsp,28) then
       48 B8 ... movabs rax, security_cookie — too generic to match on the
       prologue alone, so we skip it to avoid false positives. */
    return NULL;
}

bool is_placeholder(const char* nm) { return std::strncmp(nm, "fun_", 4) == 0; }

/* is `name` already used by a function OTHER than index `skip`? Enforces C-symbol
 * uniqueness: two functions given the same recovered name would be a duplicate
 * definition in the recompiled TU (a hard compile error). */
bool name_taken(const ds_engine* e, const char* name, size_t skip) {
    for (size_t i = 0; i < e->func_len; ++i)
        if (i != skip && std::strcmp(e->funcs[i].name, name) == 0) return true;
    return false;
}

/* Recover SAFE, high-confidence names for still-unnamed (fun_) functions from
 * their exact instruction shape. Runs AFTER the priority naming loop so it only
 * ever replaces the `fun_<rva>` fallback (is_placeholder guard) and can see the
 * targets of jmp thunks already named. Every assignment is uniqueness-guarded so
 * it can never introduce a duplicate C symbol. Gated by DS_NO_HEURNAME.
 *   getter  `mov reg,[ABS]; ret`  -> get_<abs>
 *   setter  `mov [ABS],reg; ret`  -> set_<abs>
 *   ptr     `lea rax,[ABS]; ret`  -> ptr_<abs>
 *   thunk   `jmp <internal fn>`   -> j_<target>   (IAT thunks named earlier) */
void recover_heuristic_names(ds_engine* e) {
    static const bool off = std::getenv("DS_NO_HEURNAME") != nullptr;
    if (off) return;

    /* PASS 1 — address-keyed global accessors (getter/setter/ptr). Body is EXACTLY
     * {one absolute-global access; ret}. The DS_REF_DATA + ref_target requirement
     * excludes register-relative field loads (`mov eax,[rcx]`), so this never
     * fires on the ambiguous field-accessor family. */
    for (size_t i = 0; i < e->func_len; ++i) {
        ds_func* f = &e->funcs[i];
        if (!is_placeholder(f->name)) continue;
        size_t idx = insn_index_exact(e, f->rva);
        if (idx == SIZE_MAX || idx + 1 >= e->insn_len) continue;
        const ds_insn* a = &e->insns[idx];
        const ds_insn* b = &e->insns[idx + 1];
        if (!mnem_is(b, "ret")) continue;                       /* body is {a; ret} */
        if (a->ref_type != DS_REF_DATA || a->ref_target == 0) continue; /* absolute global */
        char buf[96] = {0};
        if (mnem_is(a, "lea")) {
            std::snprintf(buf, sizeof(buf), "ptr_%llx", (unsigned long long)a->ref_target);
        } else if (mnem_is(a, "mov")) {
            /* getter `mov reg,[g]` vs setter `mov [g],reg`: Intel syntax is
             * (dest, src), so the memory operand is FIRST only for a store. */
            const char* br = std::strchr(a->operands, '[');
            bool mem_first = br && std::memchr(a->operands, ',', (size_t)(br - a->operands)) == NULL;
            std::snprintf(buf, sizeof(buf), mem_first ? "set_%llx" : "get_%llx",
                          (unsigned long long)a->ref_target);
        } else continue;
        if (buf[0] && !name_taken(e, buf, i)) ds_strlcpy(f->name, buf, sizeof(f->name));
    }

    /* PASS 2 — internal jmp thunks -> j_<target>. Separate pass so the target's
     * name (which may be a lower/higher rva) is already resolved. Excludes IAT
     * thunks (named j_<import> in the main loop, so not placeholders here). The
     * uniqueness guard covers two thunks sharing one target (lowest rva wins). */
    for (size_t i = 0; i < e->func_len; ++i) {
        ds_func* f = &e->funcs[i];
        if (!is_placeholder(f->name)) continue;
        size_t idx = insn_index_exact(e, f->rva);
        if (idx == SIZE_MAX) continue;
        const ds_insn* a = &e->insns[idx];
        if (!mnem_is(a, "jmp") || a->ref_type != DS_REF_JMP || a->ref_target == 0) continue;
        if (import_for_iat(e, a->ref_target)) continue;         /* IAT thunk: already named */
        const char* tn = NULL;
        for (size_t j = 0; j < e->func_len; ++j)
            if (e->funcs[j].rva == a->ref_target) { tn = e->funcs[j].name; break; }
        if (!tn || !tn[0]) continue;
        char buf[96];
        std::snprintf(buf, sizeof(buf), "j_%s", tn);
        if (!name_taken(e, buf, i)) ds_strlcpy(f->name, buf, sizeof(f->name));
    }
}

/* ---- names recovered from a reported-name string literal ------------------ */

/* Local mirror of Decompiler::read_cstring (decompiler.cpp:1118), which is a private
 * member of that class and so unreachable from this TU. Same contract: the rva must
 * address READ-ONLY (non-writable, non-executable) data holding a NUL-terminated,
 * printable string of at least MINLEN chars. No escaping — a reported name is a bare
 * identifier or it is not a candidate at all. */
bool sym_read_cstring(const ds_engine* e, uint64_t rva, std::string& out) {
    if (!e || !e->image) return false;
    const ds_segment* s = ds_seg_for_rva(e, rva);
    if (!s) return false;
    if ((s->flags & DS_FLAG_X) || (s->flags & DS_FLAG_W)) return false;  /* read-only data only */
    const int MINLEN = 4, MAXLEN = 96;
    std::string t;
    for (int i = 0; i < MAXLEN; ++i) {
        uint64_t at = rva + (uint64_t)i;
        if (at >= e->image_size) return false;
        uint8_t b = e->image[at];
        if (b == 0) { if ((int)t.size() < MINLEN) return false; out.swap(t); return true; }
        if (b < 0x20 || b >= 0x7f) return false;   /* non-printable -> not a string */
        t += (char)b;
    }
    return false;   /* unterminated within MAXLEN */
}

/* Would `s` be a legal, non-reserved C function name? The reserved words matter because
 * this name lands verbatim in a recompiled TU, where `double()` is a syntax error. Only
 * words >= MINLEN can survive sym_read_cstring, so shorter keywords are omitted. */
bool is_c_ident(const std::string& s) {
    if (s.size() < 4 || s.size() > 63) return false;
    if (!(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (size_t i = 1; i < s.size(); ++i)
        if (!(std::isalnum((unsigned char)s[i]) || s[i] == '_')) return false;
    static const char* const reserved[] = {
        "auto", "bool", "break", "case", "catch", "char", "class", "const", "continue",
        "default", "delete", "double", "else", "enum", "extern", "false", "float",
        "goto", "inline", "long", "namespace", "NULL", "operator", "private",
        "protected", "public", "register", "restrict", "return", "short", "signed",
        "sizeof", "static", "struct", "switch", "template", "this", "throw", "true",
        "typedef", "union", "unsigned", "virtual", "void", "volatile", "while", NULL
    };
    for (size_t i = 0; reserved[i]; ++i)
        if (s == reserved[i]) return false;
    return true;
}

/* The function whose body covers `rva`, or NULL. e->funcs is sorted and deduped by rva
 * (cfg.cpp:362-373) with f->size set (cfg.cpp:346), so this is a binary search. */
const ds_func* func_containing(const ds_engine* e, uint64_t rva) {
    size_t lo = 0, hi = e->func_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->funcs[mid].rva <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return NULL;
    const ds_func* f = &e->funcs[lo - 1];
    if (f->size && rva < f->rva + f->size) return f;
    return NULL;
}

bool func_at(const ds_engine* e, uint64_t rva) {
    size_t lo = 0, hi = e->func_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->funcs[mid].rva < rva) lo = mid + 1;
        else hi = mid;
    }
    return lo < e->func_len && e->funcs[lo].rva == rva;
}

/* Does this instruction overwrite the arg0 register, invalidating a pending literal?
 * Intel syntax puts the destination first, so a leading `rcx,` is a write to it. */
bool writes_arg0(const ds_insn* in) {
    static const char* const regs[] = { "rcx", "ecx", "cx", "cl", "ch", NULL };
    for (size_t i = 0; regs[i]; ++i) {
        size_t n = std::strlen(regs[i]);
        if (std::strncmp(in->operands, regs[i], n) == 0 &&
            (in->operands[n] == ',' || in->operands[n] == '\0'))
            return true;
    }
    return false;
}

/* Name a function after the identifier-like string literal it hands to a name-reporting
 * helper. MSVC's _invalid_parameter / _matherr report the name of the CALLER, so
 * `lea rcx,"acosf"; call H` inside fun_00070ab0 means that function IS acosf.
 *
 * Merely referencing a string proves nothing, so the accept rule is statistical and
 * caller-keyed: a helper must be fed a literal by >= QUORUM DISTINCT callers that each
 * supply a DIFFERENT identifier — the shape of a routine reporting its own name. Any
 * caller passing two different literals is a dispatcher walking a table (a TrueType
 * {cmap,glyf,head} lookup, a menu's {Aimbot,Misc,Visuals}), so it is dropped and does
 * not count toward quorum. That distinct-CALLER requirement is the whole safety
 * argument: measured on real binaries the true positive has 7 callers and the next
 * candidate has 2, and it is what rejects both table-walkers above. Validated against
 * ucrtbase.dll, which exports its math functions: 11 predictions, 11 exact matches,
 * 0 mismatches; kernel32.dll accepts nothing. Gated by DS_NO_STRNAME. */
void recover_string_names(ds_engine* e) {
    static const bool off = std::getenv("DS_NO_STRNAME") != nullptr;
    if (off) return;
    /* rcx = arg0 is the MS x64 ABI; 32-bit cdecl pushes its args, a different rule. */
    if (e->arch != DS_ARCH_X64 || !e->image) return;

    /* max measured lea->call distance is 12 insns (n=57 across three binaries); 16
     * covers every real site with margin and 24 buys nothing. */
    const size_t WIN = 16;
    const size_t QUORUM = 3;

    /* helper rva -> caller rva -> the distinct literals that caller passes it */
    std::map<uint64_t, std::map<uint64_t, std::set<std::string> > > hits;

    /* PASS A — collect (helper, caller, literal) from `lea rcx,<str>` ... `call H`. */
    for (size_t i = 0; i < e->insn_len; ++i) {
        const ds_insn* in = &e->insns[i];
        if (!mnem_is(in, "lea")) continue;
        if (in->ref_type != DS_REF_DATA || in->ref_target == 0) continue;
        /* the decoder rewrites `[rip + x]` to the absolute `rcx, [0x985f0]` */
        if (std::strncmp(in->operands, "rcx,", 4) != 0) continue;
        std::string lit;
        if (!sym_read_cstring(e, in->ref_target, lit) || !is_c_ident(lit)) continue;
        const ds_func* caller = func_containing(e, in->rva);
        if (!caller) continue;

        for (size_t j = i + 1; j < e->insn_len && j - i <= WIN; ++j) {
            const ds_insn* w = &e->insns[j];
            if (w->rva >= caller->rva + caller->size) break;   /* left the function */
            if (mnem_is(w, "ret")) break;
            if (w->ref_type == DS_REF_JMP || w->ref_type == DS_REF_BRANCH) break;
            /* any call consumes or clobbers rcx, so the first one decides — including
             * an indirect `call rax`, which carries no ref_target at all. */
            if (mnem_is(w, "call")) {
                if (w->ref_type == DS_REF_CALL && w->ref_target != 0 &&
                    !import_for_iat(e, w->ref_target) &&   /* not the call [rip] IAT form */
                    func_at(e, w->ref_target))
                    hits[w->ref_target][caller->rva].insert(lit);
                break;
            }
            if (writes_arg0(w)) break;
        }
    }

    /* PASS B — decide, then name. */
    for (std::map<uint64_t, std::map<uint64_t, std::set<std::string> > >::const_iterator
             h = hits.begin(); h != hits.end(); ++h) {
        std::map<uint64_t, std::string> named;   /* surviving caller -> its one literal */
        std::set<std::string> idents;
        for (std::map<uint64_t, std::set<std::string> >::const_iterator
                 c = h->second.begin(); c != h->second.end(); ++c) {
            if (c->second.size() != 1) continue;   /* table-walker, not a name report */
            const std::string& id = *c->second.begin();
            named[c->first] = id;
            idents.insert(id);
        }
        if (named.size() < QUORUM || idents.size() < QUORUM) continue;

        for (std::map<uint64_t, std::string>::const_iterator n = named.begin();
             n != named.end(); ++n) {
            for (size_t i = 0; i < e->func_len; ++i) {
                ds_func* f = &e->funcs[i];
                if (f->rva != n->first) continue;
                /* only ever upgrade the fun_ fallback, never a real symbol; the
                 * uniqueness guard covers two callers reporting the same name. */
                if (is_placeholder(f->name) && !name_taken(e, n->second.c_str(), i))
                    ds_strlcpy(f->name, n->second.c_str(), sizeof(f->name));
                break;
            }
        }
    }
}

} // namespace

extern "C" int ds_engine_resolve_symbols(ds_engine* e) {
    if (!e) return 1;

    /* The PE AddressOfEntryPoint of a DLL is the CRT bootstrap (_DllMainCRTStartup),
     * NOT the user's DllMain — that runs later, dispatched by the CRT. Naming the
     * entry "DllMain" mislabels the wrapper and hides the real user callback, so use
     * the accurate IDA-style "DllEntryPoint" (an EXE entry stays "start"). */
    const char* entry_name = e->is_dll ? "DllEntryPoint" : "start";

    for (size_t i = 0; i < e->func_len; ++i) {
        ds_func* f = &e->funcs[i];
        f->name[0] = '\0';

        /* (1) seeded export/debug symbol */
        const char* sym = seeded_symbol(e, f->rva);
        if (sym) {
            ds_strlcpy(f->name, sym, sizeof(f->name));
            continue;
        }

        /* (2) entry point */
        if (e->entry_set && f->rva == e->entry_rva) {
            ds_strlcpy(f->name, entry_name, sizeof(f->name));
            continue;
        }

        /* (3) import thunk -> j_<import> */
        const char* imp = import_thunk_name(e, f->rva);
        if (imp) {
            char buf[96];
            std::snprintf(buf, sizeof(buf), "j_%s", imp);
            ds_strlcpy(f->name, buf, sizeof(f->name));
            continue;
        }

        /* (4) FLIRT-ish signatures */
        size_t idx = insn_index_exact(e, f->rva);
        if (idx != SIZE_MAX) {
            const char* fl = flirt_match(&e->insns[idx], e, idx);
            if (fl) {
                ds_strlcpy(f->name, fl, sizeof(f->name));
                continue;
            }
        }

        /* (5) fallback */
        char buf[96];
        std::snprintf(buf, sizeof(buf), "fun_%08llx",
                      (unsigned long long)f->rva);
        ds_strlcpy(f->name, buf, sizeof(f->name));
    }

    /* (6) upgrade fun_ placeholders from a self-reported name literal. Runs BEFORE the
     * shape heuristics: a reported name outranks a j_/get_/set_ shape name, and going
     * first lets the thunk pass below render `j_acosf` instead of `j_fun_00070ab0`. */
    recover_string_names(e);

    /* (7) upgrade remaining fun_ placeholders with safe shape heuristics */
    recover_heuristic_names(e);

    return 0;
}
