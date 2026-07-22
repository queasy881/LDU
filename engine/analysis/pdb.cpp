/*
 * pdb.cpp — ds_engine_load_pdb(): recover real function names from a PDB.
 *
 * A stripped binary gives us export names only; everything else renders as
 * fun_<rva>. When the compiler emitted a PDB, the PE debug directory carries a
 * CodeView "RSDS" record naming it, and that PDB has a name for every function
 * the compiler saw — statics and inlined-away helpers included. On the fixture
 * in _qa/pdbtest only 1 of 4 functions is exported; the other 3 can be named
 * from nothing but the PDB.
 *
 * Seeding runs BEFORE build_cfg's function-start collection (cfg.cpp), so a
 * PDB name both names a function and, via `consider(e->symbols[i].rva)`, can
 * recover one that nothing calls. It runs before ds_engine_scan_rtti so that
 * the PDB — the authoritative source — wins over an RTTI-reconstructed name
 * (rtti.cpp skips any rva that is already seeded).
 *
 * dbghelp is resolved dynamically (GetProcAddress), mirroring demangle_msvc()
 * in decompiler.cpp: the engine links capstone and nothing else, so adding
 * dbghelp.lib to the link line is not an option. Unlike that call site this TU
 * needs SYMBOL_INFO and IMAGEHLP_MODULE64, whose layouts are contracts checked
 * by dbghelp at runtime (SizeOfStruct) — hand-declaring them risks silent
 * corruption for no gain, so the real SDK headers are included here. They stay
 * confined to this small TU; decompiler.cpp's 19.5k lines keep their hand-rolled
 * dllimport decls.
 *
 * Gated by DS_NO_PDB.
 */
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>
#endif

#include "disasm.h"
#include "engine_internal.h"
#include "rust_demangle.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <set>
#include <mutex>

#if defined(_WIN32)
namespace {

/* the identifier budget: ds_symbol.name is 96 bytes, so ds_strlcpy keeps 95. */
const size_t NAME_MAX_LEN = sizeof(((ds_symbol*)0)->name) - 1;
/* on a collision we append "_<rva hex>" (1 + up to 8), so the base keeps 86. */
const size_t NAME_BASE_LEN = NAME_MAX_LEN - 9;

/* bounds-checked little-endian reads over the flat RVA-indexed image. */
bool read_u16(const ds_engine* e, uint64_t rva, uint16_t& out) {
    if (rva + 2 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 2);
    return true;
}
bool read_u32(const ds_engine* e, uint64_t rva, uint32_t& out) {
    if (rva + 4 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 4);
    return true;
}

bool already_seeded(const ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].rva == rva && e->symbols[i].name[0]) return true;
    return false;
}

/* The identifier the back end will really emit for a seeded name: the name is
 * truncated to 95 by ds_strlcpy, and sani() (decompiler.cpp) then maps every
 * byte outside [A-Za-z0-9_] to '_'. Both steps MERGE distinct PDB names, so the
 * dedupe key has to be computed on the post-truncation, post-sani form or it
 * misses precisely the cases that occur: CRT template soup routinely differs
 * only past char 95 (`...parse_into_buffer<unsigned __int64,16>` vs `,10>`),
 * and `A::b` collides with an `A__b` elsewhere. Mirrors sani() exactly,
 * including its leading-digit guard — demangle_msvc() inside sani() is a no-op
 * here because SYMOPT_UNDNAME means dbghelp hands us undecorated names. */
std::string render_key(const std::string& raw) {
    std::string s = raw.substr(0, NAME_MAX_LEN);
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            s[i] = '_';
    }
    if (s.empty() || (s[0] >= '0' && s[0] <= '9')) s = "_" + s;
    return s;
}

/* ---- the RSDS record ----------------------------------------------------- */

struct CodeView {
    std::string path;
    GUID        guid;
    uint32_t    age;
};

/* Locate DataDirectory[6] (debug) and pull the CodeView RSDS entry out of it.
 * Every read is against the FLAT RVA-INDEXED image (headers at rva 0, sections
 * at their rvas — crates/binary-parser build_image), which is why the blob is
 * read at IMAGE_DEBUG_DIRECTORY.AddressOfRawData and never PointerToRawData:
 * the file offset addresses nothing in this buffer and would read garbage.
 * pe_data_dir()/compute_pe_tables() in decompiler.cpp are file-local statics,
 * so the header walk is re-done here — the same precedent rtti.cpp sets with
 * its own readers. */
bool find_codeview(const ds_engine* e, CodeView& cv) {
    uint16_t mz = 0;
    if (!read_u16(e, 0, mz) || mz != 0x5a4d) return false;      /* "MZ" */
    uint32_t nt = 0;
    if (!read_u32(e, 0x3c, nt)) return false;
    uint32_t sig = 0;
    if (!read_u32(e, nt, sig) || sig != 0x00004550) return false; /* "PE\0\0" */

    uint16_t magic = 0;
    if (!read_u16(e, nt + 24, magic)) return false;
    bool pe32plus = (magic == 0x20b);
    if (!pe32plus && magic != 0x10b) return false;

    /* NumberOfRvaAndSizes must actually cover index 6 before we index it. */
    uint32_t ndirs = 0;
    if (!read_u32(e, nt + 24 + (pe32plus ? 108 : 92), ndirs) || ndirs < 7) return false;

    uint64_t dd = nt + 24 + (pe32plus ? 112 : 96) + 6 * 8;
    uint32_t dbg_rva = 0, dbg_size = 0;
    if (!read_u32(e, dd, dbg_rva) || !read_u32(e, dd + 4, dbg_size)) return false;
    if (!dbg_rva || !dbg_size) return false;

    for (uint32_t off = 0; off + 28 <= dbg_size; off += 28) {
        uint64_t ent = (uint64_t)dbg_rva + off;
        uint32_t type = 0, szdata = 0, aor = 0;
        if (!read_u32(e, ent + 12, type) || !read_u32(e, ent + 16, szdata) ||
            !read_u32(e, ent + 20, aor))
            return false;
        if (type != 2 /* IMAGE_DEBUG_TYPE_CODEVIEW */) continue;
        /* "RSDS" + GUID(16) + age(4) + at least one path byte */
        if (szdata < 25 || !aor) continue;
        if ((uint64_t)aor + szdata > e->image_size) continue;

        uint32_t rs = 0;
        if (!read_u32(e, aor, rs) || rs != 0x53445352) continue;  /* "RSDS" */

        std::memcpy(&cv.guid, e->image + aor + 4, 16);
        if (!read_u32(e, aor + 20, cv.age)) continue;

        /* NUL-terminated printable path, bounded by SizeOfData (rtti.cpp's
         * read_rtti_name discipline: anything else is not a real record). */
        const char* p = (const char*)(e->image + aor + 24);
        std::string s;
        bool ok = false;
        for (uint32_t i = 0; i + 24 < szdata; ++i) {
            char c = p[i];
            if (c == '\0') { ok = true; break; }
            if (c < 0x20 || (unsigned char)c > 0x7e) break;
            s.push_back(c);
        }
        if (!ok || s.empty()) continue;
        cv.path = s;
        return true;
    }
    return false;
}

/* ---- dbghelp, resolved dynamically -------------------------------------- */

typedef DWORD   (WINAPI* SymSetOptionsFn)(DWORD);
typedef BOOL    (WINAPI* SymInitializeFn)(HANDLE, PCSTR, BOOL);
typedef DWORD64 (WINAPI* SymLoadModuleExFn)(HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD,
                                            PMODLOAD_DATA, DWORD);
typedef BOOL    (WINAPI* SymEnumSymbolsFn)(HANDLE, ULONG64, PCSTR,
                                           PSYM_ENUMERATESYMBOLS_CALLBACK, PVOID);
typedef BOOL    (WINAPI* SymGetModuleInfo64Fn)(HANDLE, DWORD64, PIMAGEHLP_MODULE64);
typedef BOOL    (WINAPI* SymCleanupFn)(HANDLE);

struct Dbghelp {
    SymSetOptionsFn      set_options;
    SymInitializeFn      init;
    SymLoadModuleExFn    load;
    SymEnumSymbolsFn     enum_syms;
    SymGetModuleInfo64Fn mod_info;
    SymCleanupFn         cleanup;
    bool ok() const {
        return set_options && init && load && enum_syms && mod_info && cleanup;
    }
};

const Dbghelp* dbghelp() {
    static Dbghelp d;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE h = LoadLibraryA("dbghelp.dll");
        if (h) {
            d.set_options = (SymSetOptionsFn)GetProcAddress(h, "SymSetOptions");
            d.init        = (SymInitializeFn)GetProcAddress(h, "SymInitialize");
            d.load        = (SymLoadModuleExFn)GetProcAddress(h, "SymLoadModuleEx");
            d.enum_syms   = (SymEnumSymbolsFn)GetProcAddress(h, "SymEnumSymbols");
            d.mod_info    = (SymGetModuleInfo64Fn)GetProcAddress(h, "SymGetModuleInfo64");
            d.cleanup     = (SymCleanupFn)GetProcAddress(h, "SymCleanup");
        }
    }
    return d.ok() ? &d : nullptr;
}

struct SeedCtx {
    ds_engine*             e;
    std::set<std::string>* used;
    size_t                 seeded;
};

BOOL CALLBACK on_symbol(PSYMBOL_INFO si, ULONG, PVOID ctx) {
    SeedCtx* c = (SeedCtx*)ctx;
    if (!si || si->Tag != 5 /* SymTagFunction (cvconst.h) */) return TRUE;
    if (si->Address < c->e->base) return TRUE;

    uint64_t rva = si->Address - c->e->base;
    if (!ds_rva_is_exec(c->e, rva)) return TRUE;
    /* an export already named this rva, and that name is equally authoritative;
     * this is also what makes a second build_cfg pass a no-op. */
    if (already_seeded(c->e, rva)) return TRUE;

    size_t n = si->NameLen;
    if (n == 0 || n > 4096) return TRUE;
    std::string raw(si->Name, ::strnlen(si->Name, n));
    if (raw.empty()) return TRUE;

    /* Rust functions reach the PDB as `_ZN..17h<hash>E` (legacy) or `_R..` (v0)
     * manglings — dbghelp's C++ undecorator leaves both untouched. Demangle to a
     * real module path (core::fmt::Formatter::pad) so the whole binary, headers
     * and call sites alike, reads with names instead of hash noise. Non-Rust
     * symbols (including `_R*` C runtime lookalikes) return "" and are kept. */
    if (!std::getenv("DS_NO_RUSTNAME")) {
        std::string rd = ds_rust_demangle(raw);
        if (!rd.empty()) raw.swap(rd);
    }

    std::string name = raw.substr(0, NAME_MAX_LEN);
    std::string key = render_key(name);
    if (c->used->count(key)) {
        /* Real and common, not hypothetical: pdbtest.dll's own CRT ships
         * get_wide at both 63b68 and 63b6c, and two output_processor helpers
         * whose names first differ at char 100. symbols.cpp's priority-1 path
         * copies a seeded name in unguarded, so a duplicate here becomes a
         * duplicate C definition — the dedupe has to happen at the source. */
        char sfx[16];
        std::snprintf(sfx, sizeof sfx, "_%llx", (unsigned long long)rva);
        name = raw.substr(0, NAME_BASE_LEN) + sfx;
        key = render_key(name);
        if (c->used->count(key)) return TRUE;  /* fun_<rva> beats a wrong name */
    }
    c->used->insert(key);
    ds_engine_add_symbol(c->e, rva, name.c_str());
    c->seeded++;
    return TRUE;
}

} // namespace
#endif  /* _WIN32 */

extern "C" void ds_engine_load_pdb(ds_engine* e) {
#if defined(_WIN32)
    static const bool off = std::getenv("DS_NO_PDB") != nullptr;
    if (off || !e || !e->image || !e->image_size) return;

    const bool report = std::getenv("DS_PDB_REPORT") != nullptr;
    CodeView cv;
    if (!find_codeview(e, cv)) { if (report) std::fprintf(stderr, "[pdb] no codeview record\n"); return; }
    /* The RSDS path is absolute and baked in at link time; ds_engine has no
     * path field for the binary itself, so this is the only pdb we can name.
     * A binary copied off its build machine simply keeps fun_<rva>. */
    if (GetFileAttributesA(cv.path.c_str()) == INVALID_FILE_ATTRIBUTES) { if (report) std::fprintf(stderr, "[pdb] file not found: %s\n", cv.path.c_str()); return; }

    const Dbghelp* d = dbghelp();
    if (!d) { if (report) std::fprintf(stderr, "[pdb] dbghelp unavailable\n"); return; }

    /* dbghelp's Sym* state is global per handle and is NOT thread-safe, and the
     * dump tool decompiles across N threads (the get_pe_tables cache in
     * decompiler.cpp guards its shared state the same way). `e` is a unique
     * non-null handle to key the session with. */
    static std::mutex m;
    std::lock_guard<std::mutex> lk(m);

    HANDLE h = (HANDLE)e;
    d->set_options(SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS | SYMOPT_EXACT_SYMBOLS);
    if (!d->init(h, NULL, FALSE)) return;

    /* Load the .pdb directly: given an explicit pdb path dbghelp needs neither
     * the dll on disk nor a live process, which is what makes this work from an
     * image ds_engine only holds in memory. */
    if (!d->load(h, NULL, cv.path.c_str(), NULL, e->base, (DWORD)e->image_size, NULL, 0)) {
        if (report) std::fprintf(stderr, "[pdb] load failed\n");
        d->cleanup(h);
        return;
    }

    /* Loading by explicit path means dbghelp never checked the pdb against the
     * image — a stale pdb left beside a rebuilt binary would hand us names for
     * the WRONG addresses, i.e. confidently wrong C. The RSDS GUID+age is the
     * identity the linker recorded, so require the loaded pdb to match it. */
    IMAGEHLP_MODULE64 mi;
    std::memset(&mi, 0, sizeof mi);
    mi.SizeOfStruct = sizeof mi;
    if (!d->mod_info(h, e->base, &mi) ||
        std::memcmp(&mi.PdbSig70, &cv.guid, sizeof(GUID)) != 0 ||
        mi.PdbAge != cv.age) {
        if (report) std::fprintf(stderr, "[pdb] identity mismatch (stale/wrong pdb)\n");
        d->cleanup(h);
        return;
    }

    SeedCtx ctx;
    ctx.e = e;
    std::set<std::string> used;
    /* names already seeded (exports) are taken as far as C is concerned. */
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].name[0]) used.insert(render_key(e->symbols[i].name));
    ctx.used = &used;
    ctx.seeded = 0;

    d->enum_syms(h, e->base, "*", on_symbol, &ctx);
    d->cleanup(h);

    if (std::getenv("DS_PDB_REPORT"))
        std::fprintf(stderr, "[pdb] %s: seeded %zu names\n", cv.path.c_str(), ctx.seeded);
#else
    (void)e;
#endif
}
