/*
 * gopclntab.cpp — ds_engine_load_go_pclntab(): recover real function names from
 * a Go binary's pclntab.
 *
 * A Go executable is statically linked and exports almost nothing, so every one
 * of its functions rendered as fun_<rva>: git-lfs showed 12,465 anonymous
 * functions. But Go embeds its own symbol table — runtime.pclntab, the structure
 * the runtime itself uses to build stack traces — and it names EVERY function the
 * linker kept. On that same binary it carries 14,364 names, `syscall.init` and
 * `internal/abi.(*RegArgs).Dump` among them. It is not debug information and is
 * not stripped by anything short of a dedicated obfuscator: the runtime needs it,
 * so it ships in release builds.
 *
 * This is the same category of source as pdb.cpp — authoritative, from the
 * producer — so it runs in the same place, BEFORE build_cfg collects function
 * starts (cfg.cpp). Seeding e->symbols there means a name both labels a function
 * and, via `consider(e->symbols[i].rva)`, RECOVERS one that nothing calls: Go's
 * indirect-heavy dispatch leaves plenty of those (the gap above is ~1,900
 * functions). It runs after the PDB loader, which stays authoritative — a Go
 * program built with a PDB is a cgo build whose PDB names the C side.
 *
 * FORMAT. The header is versioned by a magic word, and the layout changed twice:
 *
 *   0xfffffffb  go1.2    — different structure entirely; NOT handled (see below)
 *   0xfffffffa  go1.16   — offset-table header, absolute entry PCs
 *   0xfffffff0  go1.18   — adds textStart; entry PCs become 32-bit offsets
 *   0xfffffff1  go1.20   — same layout as go1.18
 *
 * go1.2 is from 2013 and stores the func table inline in a wholly different
 * shape; it is skipped rather than guessed at, because a misparse here would
 * invent confident, wrong names for every function in the binary, and a wrong
 * name is worse than fun_<rva>.
 *
 * FINDING IT. There is no directory entry pointing at pclntab in a PE, so the
 * image is scanned for the magic. The magic alone is a weak signal — four bytes
 * that occur in ordinary data — so a candidate is accepted only after its whole
 * header validates (reserved bytes zero, plausible minLC/ptrSize, table offsets
 * inside the image) AND a sample of its entries parse to printable names at
 * executable RVAs. On git-lfs the raw magic matches several times and exactly one
 * candidate survives. If none survives, nothing is seeded and the binary is
 * treated as it is today.
 *
 * Names are stored verbatim (`internal/abi.(*RegArgs).Dump`); sani() in
 * decompiler.cpp maps them to C identifiers at emission.
 *
 * Gated by DS_NO_GOPCLNTAB.
 */

#include "disasm.h"
#include "engine_internal.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

bool rd_u32(const ds_engine* e, uint64_t rva, uint32_t& out) {
    if (rva + 4 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 4);
    return true;
}
bool rd_u64(const ds_engine* e, uint64_t rva, uint64_t& out) {
    if (rva + 8 > e->image_size) return false;
    std::memcpy(&out, e->image + rva, 8);
    return true;
}

/* A Go symbol name: printable ASCII, no spaces, NUL-terminated within a bound.
 * Go names can be long (generic instantiations carry their type arguments), so
 * the cap is generous; anything past it is not a name we want to trust. */
std::string rd_name(const ds_engine* e, uint64_t rva) {
    std::string s;
    for (uint64_t i = 0; i < 1024 && rva + i < e->image_size; ++i) {
        char c = (char)e->image[rva + i];
        if (c == '\0') return s;
        if (c < 0x21 || c > 0x7e) return "";   /* control, space or high byte */
        s.push_back(c);
    }
    return "";
}

struct Header {
    uint64_t rva = 0;          /* pclntab base */
    uint32_t magic = 0;
    uint8_t  ptr_size = 8;
    uint64_t nfunc = 0;
    uint64_t text_start = 0;   /* go1.18+ only */
    uint64_t funcname_off = 0;
    uint64_t pcln_off = 0;     /* functab */
    bool     wide_functab = false;  /* go1.16: uintptr pairs, absolute entry */
};

/* One functab entry -> (rva, name). Returns false if anything is out of range. */
bool entry_at(const ds_engine* e, const Header& h, uint64_t i,
              uint64_t& rva_out, std::string& name_out) {
    const uint64_t ft = h.rva + h.pcln_off;
    uint64_t entry = 0, funcoff = 0;
    if (h.wide_functab) {
        /* go1.16: { entry uintptr; funcoff uintptr } — entry is an absolute VA */
        if (!rd_u64(e, ft + i * 16, entry)) return false;
        if (!rd_u64(e, ft + i * 16 + 8, funcoff)) return false;
        if (entry < e->base) return false;
        rva_out = entry - e->base;
    } else {
        /* go1.18+: { entryOff uint32; funcOff uint32 } — entryOff is relative
         * to textStart, which is itself an absolute VA */
        uint32_t eo = 0, fo = 0;
        if (!rd_u32(e, ft + i * 8, eo)) return false;
        if (!rd_u32(e, ft + i * 8 + 4, fo)) return false;
        entry = h.text_start + eo;
        funcoff = fo;
        if (entry < e->base) return false;
        rva_out = entry - e->base;
    }
    /* _func.nameOff: int32, at +4 (go1.18+, entryOff is u32) or +8 (go1.16,
     * entry is a uintptr). Relative to the funcnametab. */
    const uint64_t fn = ft + funcoff;
    uint32_t raw = 0;
    if (!rd_u32(e, fn + (h.wide_functab ? 8 : 4), raw)) return false;
    const int32_t name_off = (int32_t)raw;
    if (name_off < 0) return false;
    name_out = rd_name(e, h.rva + h.funcname_off + (uint64_t)name_off);
    return !name_out.empty();
}

/* Parse and validate a candidate header at `rva`. */
bool parse_header(const ds_engine* e, uint64_t rva, Header& h) {
    uint32_t magic = 0;
    if (!rd_u32(e, rva, magic)) return false;
    if (magic != 0xfffffff1u && magic != 0xfffffff0u && magic != 0xfffffffau)
        return false;
    if (rva + 0x48 > e->image_size) return false;
    if (e->image[rva + 4] != 0 || e->image[rva + 5] != 0) return false;   /* pad */
    const uint8_t min_lc = e->image[rva + 6], ptr_size = e->image[rva + 7];
    if (min_lc != 1 && min_lc != 2 && min_lc != 4) return false;
    if (ptr_size != 4 && ptr_size != 8) return false;
    if (ptr_size != 8) return false;   /* x64 image; a 32-bit table here is a false hit */

    uint64_t nfunc = 0;
    if (!rd_u64(e, rva + 0x08, nfunc)) return false;
    if (nfunc < 8 || nfunc > 4000000) return false;

    h = Header();
    h.rva = rva; h.magic = magic; h.ptr_size = ptr_size; h.nfunc = nfunc;

    /* go1.18+ inserts textStart before the offset block; go1.16 does not. */
    const bool has_text_start = (magic == 0xfffffff1u || magic == 0xfffffff0u);
    uint64_t p = rva + 0x18;
    if (has_text_start) {
        if (!rd_u64(e, p, h.text_start)) return false;
        p += 8;
    } else {
        h.wide_functab = true;
    }
    uint64_t cu_off = 0, filetab_off = 0, pctab_off = 0;
    if (!rd_u64(e, p + 0x00, h.funcname_off)) return false;
    if (!rd_u64(e, p + 0x08, cu_off)) return false;
    if (!rd_u64(e, p + 0x10, filetab_off)) return false;
    if (!rd_u64(e, p + 0x18, pctab_off)) return false;
    if (!rd_u64(e, p + 0x20, h.pcln_off)) return false;

    /* every table must live inside the image, after the header */
    const uint64_t lim = e->image_size - rva;
    if (h.funcname_off >= lim || h.pcln_off >= lim ||
        cu_off >= lim || filetab_off >= lim || pctab_off >= lim)
        return false;
    /* the functab must be big enough for nfunc entries plus the end sentinel */
    const uint64_t stride = h.wide_functab ? 16 : 8;
    if (h.pcln_off + (nfunc + 1) * stride > lim) return false;
    if (has_text_start && h.text_start < e->base) return false;
    return true;
}

/* A header can validate by luck; require that its DATA parses too. Sample across
 * the whole table rather than the first few, so a coincidental prefix cannot
 * carry a false candidate. */
bool validate_entries(const ds_engine* e, const Header& h) {
    const uint64_t probes = 16;
    uint64_t ok = 0, tried = 0;
    for (uint64_t k = 0; k < probes; ++k) {
        const uint64_t i = (h.nfunc * k) / probes;
        uint64_t rva = 0; std::string nm;
        ++tried;
        if (!entry_at(e, h, i, rva, nm)) continue;
        if (!ds_rva_is_exec(e, rva)) continue;
        ++ok;
    }
    return tried > 0 && ok == tried;
}

}  // namespace

extern "C" void ds_engine_load_go_pclntab(ds_engine* e) {
    if (std::getenv("DS_NO_GOPCLNTAB")) return;
    if (!e || !e->image || e->image_size < 0x1000) return;
    if (e->arch != DS_ARCH_X64) return;   /* only the 64-bit layout is implemented */

    /* Scan 8-aligned words for the magic: the Go linker aligns runtime.pclntab,
     * and stepping 8 keeps this a fast pass over a multi-MB image. */
    Header best;
    bool found = false;
    for (uint64_t rva = 0; rva + 0x48 <= e->image_size; rva += 8) {
        const uint8_t b3 = e->image[rva + 3];
        if (b3 != 0xff) continue;                       /* cheap reject */
        Header h;
        if (!parse_header(e, rva, h)) continue;
        if (!validate_entries(e, h)) continue;
        best = h; found = true;
        break;
    }
    if (!found) return;

    uint64_t named = 0;
    for (uint64_t i = 0; i < best.nfunc; ++i) {
        uint64_t rva = 0; std::string nm;
        if (!entry_at(e, best, i, rva, nm)) continue;
        if (!ds_rva_is_exec(e, rva)) continue;
        /* Do not overwrite a name from a stronger source (PDB, exports). */
        bool taken = false;
        for (size_t s = 0; s < e->symbol_len; ++s)
            if (e->symbols[s].rva == rva && e->symbols[s].name[0]) { taken = true; break; }
        if (taken) continue;
        ds_engine_add_symbol(e, rva, nm.c_str());
        ++named;
    }
    if (std::getenv("DS_DBG_GOPCLNTAB"))
        std::fprintf(stderr, "[gopclntab] magic=%#x @rva %#llx nfunc=%llu named=%llu\n",
                     best.magic, (unsigned long long)best.rva,
                     (unsigned long long)best.nfunc, (unsigned long long)named);
}
