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

#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

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

    /* (6) upgrade remaining fun_ placeholders with safe shape heuristics */
    recover_heuristic_names(e);

    return 0;
}
