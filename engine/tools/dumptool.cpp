/*
 * dumptool.cpp — fast MULTITHREADED dumper for the DisasmStudio engine.
 *
 * Loads a PE (EXE/DLL), seeds + analyzes the engine ONCE, then decompiles every
 * function across N worker threads (default 10) into _qa/pairs/fn_<rva>.txt,
 * byte-compatible with the Rust `dump_pairs` test but ~N× faster.
 *
 * ds_decompile() is thread-safe on a shared engine: it only READS the (immutable
 * after analysis) ds_engine and builds all per-function state in a local
 * Decompiler instance — so all workers share one analyzed engine.
 *
 * Env:
 *   DS_REAL_BIN    input PE (required)
 *   DS_PAIRS_CAP   max functions (default 100000 = all)
 *   DS_PAIRS_RVAS  comma list of hex rvas; if set, ONLY these
 *   DS_DUMP_THREADS worker count (default 10)
 *   DS_DUMP_OUT    output dir (default C:\Users\User\Downloads\sd\_qa\pairs)
 *
 * Build: see engine/tools/build_dumptool.sh
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include "disasm.h"

// ---------------------------------------------------------------- PE loader
struct Seg { std::string name; uint64_t rva, vsize; uint32_t flags; };
struct Sym { uint64_t rva; std::string name; };
struct Imp { uint64_t iat_rva; std::string name; };

struct Loaded {
    std::vector<uint8_t> image;              // flat, laid out at RVAs
    uint64_t base = 0, entry = 0;
    int is_dll = 0; ds_arch arch = DS_ARCH_X64;
    std::vector<Seg> segs;
    std::vector<Sym> exports;
    std::vector<Imp> imports;
    const uint8_t* at(uint64_t rva, size_t need = 1) const {
        if (rva + need > image.size()) return nullptr;
        return image.data() + rva;
    }
    const char* str(uint64_t rva) const {
        if (rva >= image.size()) return nullptr;
        const char* s = (const char*)image.data() + rva;
        size_t max = image.size() - rva;
        return memchr(s, 0, max) ? s : nullptr;   // must be NUL-terminated in-image
    }
};

static bool load_pe(const char* path, Loaded& L) {
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "cannot open %s\n", path); return false; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    std::vector<uint8_t> raw(sz);
    if (fread(raw.data(), 1, sz, fp) != (size_t)sz) { fclose(fp); return false; }
    fclose(fp);

    if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = (IMAGE_DOS_HEADER*)raw.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "not a PE\n"); return false; }
    uint32_t peoff = dos->e_lfanew;
    if (peoff + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER) > raw.size()) return false;
    if (*(uint32_t*)(raw.data() + peoff) != IMAGE_NT_SIGNATURE) { fprintf(stderr, "no PE sig\n"); return false; }

    auto* fh = (IMAGE_FILE_HEADER*)(raw.data() + peoff + 4);
    uint16_t nsec = fh->NumberOfSections;
    L.is_dll = (fh->Characteristics & IMAGE_FILE_DLL) ? 1 : 0;
    L.arch = (fh->Machine == IMAGE_FILE_MACHINE_I386) ? DS_ARCH_X86 : DS_ARCH_X64;

    uint8_t* opt = raw.data() + peoff + 4 + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = *(uint16_t*)opt;
    uint64_t image_size = 0, sect_align = 0, hdr_size = 0;
    const IMAGE_DATA_DIRECTORY* dd = nullptr; uint32_t dd_count = 0;
    uint32_t entry_rva = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* o = (IMAGE_OPTIONAL_HEADER64*)opt;
        L.base = o->ImageBase; entry_rva = o->AddressOfEntryPoint;
        image_size = o->SizeOfImage; sect_align = o->SectionAlignment; hdr_size = o->SizeOfHeaders;
        dd = o->DataDirectory; dd_count = o->NumberOfRvaAndSizes;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto* o = (IMAGE_OPTIONAL_HEADER32*)opt;
        L.base = o->ImageBase; entry_rva = o->AddressOfEntryPoint;
        image_size = o->SizeOfImage; sect_align = o->SectionAlignment; hdr_size = o->SizeOfHeaders;
        dd = o->DataDirectory; dd_count = o->NumberOfRvaAndSizes;
    } else { fprintf(stderr, "bad optional magic 0x%x\n", magic); return false; }
    L.entry = entry_rva;

    // ---- build the flat image ----
    L.image.assign(image_size, 0);
    size_t copyhdr = std::min<size_t>(hdr_size, raw.size());
    memcpy(L.image.data(), raw.data(), std::min<size_t>(copyhdr, image_size));

    auto* sec = (IMAGE_SECTION_HEADER*)(opt + fh->SizeOfOptionalHeader);
    for (uint16_t i = 0; i < nsec; ++i) {
        const IMAGE_SECTION_HEADER& s = sec[i];
        uint64_t va = s.VirtualAddress;
        uint64_t vsize = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        uint64_t rawoff = s.PointerToRawData, rawsz = s.SizeOfRawData;
        if (va < image_size && rawoff < raw.size()) {
            uint64_t n = std::min<uint64_t>({ rawsz, image_size - va, raw.size() - rawoff });
            memcpy(L.image.data() + va, raw.data() + rawoff, n);
        }
        char nm[9] = {0}; memcpy(nm, s.Name, 8);
        uint32_t f = 0;
        if (s.Characteristics & IMAGE_SCN_MEM_READ)    f |= DS_FLAG_R;
        if (s.Characteristics & IMAGE_SCN_MEM_WRITE)   f |= DS_FLAG_W;
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) f |= DS_FLAG_X;
        L.segs.push_back({ nm, va, vsize, f });
    }

    bool is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // ---- exports ----
    if (dd_count > IMAGE_DIRECTORY_ENTRY_EXPORT && dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        uint64_t er = dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (auto* p = L.at(er, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            auto* ed = (const IMAGE_EXPORT_DIRECTORY*)p;
            const uint32_t* funcs = (const uint32_t*)L.at(ed->AddressOfFunctions, 4);
            const uint32_t* names = (const uint32_t*)L.at(ed->AddressOfNames, 4);
            const uint16_t* ords  = (const uint16_t*)L.at(ed->AddressOfNameOrdinals, 2);
            if (funcs && names && ords) {
                for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
                    const char* nm = L.str(names[i]);
                    uint16_t ord = ords[i];
                    if (nm && ord < ed->NumberOfFunctions && funcs[ord])
                        L.exports.push_back({ funcs[ord], nm });
                }
            }
        }
    }

    // ---- imports ----
    if (dd_count > IMAGE_DIRECTORY_ENTRY_IMPORT && dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        uint64_t ir = dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        for (uint32_t d = 0;; ++d) {
            auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)L.at(ir + d * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                                                            sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!imp || (imp->OriginalFirstThunk == 0 && imp->FirstThunk == 0)) break;
            uint64_t int_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
            uint64_t iat_rva = imp->FirstThunk;
            uint64_t psz = is64 ? 8 : 4;
            for (uint32_t k = 0;; ++k) {
                const uint8_t* tp = L.at(int_rva + k * psz, psz);
                if (!tp) break;
                uint64_t thunk = is64 ? *(const uint64_t*)tp : *(const uint32_t*)tp;
                if (thunk == 0) break;
                uint64_t hi = is64 ? (1ull << 63) : (1ull << 31);
                uint64_t slot = iat_rva + k * psz;
                if (!(thunk & hi)) {                       // import by name
                    const char* nm = L.str((thunk & (is64 ? 0x7fffffffffffffffull : 0x7fffffffull)) + 2);
                    if (nm) L.imports.push_back({ slot, nm });
                }
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------- helpers
static std::string getenv_s(const char* k) { const char* v = getenv(k); return v ? v : ""; }

int main() {
    std::string bin = getenv_s("DS_REAL_BIN");
    if (bin.empty()) { fprintf(stderr, "set DS_REAL_BIN\n"); return 2; }
    std::string outdir = getenv_s("DS_DUMP_OUT");
    if (outdir.empty()) outdir = R"(C:\Users\User\Downloads\sd\_qa\pairs)";
    int nthreads = 10;
    if (auto e = getenv("DS_DUMP_THREADS")) nthreads = std::max(1, atoi(e));
    size_t cap = 100000;
    if (auto e = getenv("DS_PAIRS_CAP")) cap = (size_t)strtoull(e, nullptr, 10);

    std::vector<uint64_t> only;
    if (auto e = getenv("DS_PAIRS_RVAS")) {
        std::string s = e, tok; for (char c : s) {
            if (c == ',') { if (!tok.empty()) only.push_back(strtoull(tok.c_str(), nullptr, 16)), tok.clear(); }
            else if (c != ' ') { if (tok.rfind("0x", 0) == 0 || tok.rfind("0X", 0) == 0) {} tok += c; }
        }
        if (!tok.empty()) only.push_back(strtoull(tok.c_str(), nullptr, 16));
    }

    Loaded L;
    if (!load_pe(bin.c_str(), L)) return 1;

    // ---- create + seed the engine (ONCE) ----
    ds_engine* e = ds_engine_create(L.image.data(), L.image.size(), L.base, L.arch);
    if (!e) { fprintf(stderr, "engine create failed\n"); return 1; }
    ds_engine_set_is_dll(e, L.is_dll);
    ds_engine_set_entry_rva(e, L.entry);
    for (auto& s : L.segs) ds_engine_add_segment(e, s.name.c_str(), s.rva, s.vsize, s.flags);
    for (auto& x : L.exports) { ds_engine_add_symbol(e, x.rva, x.name.c_str()); ds_engine_add_entry(e, x.rva); }
    ds_engine_add_entry(e, L.entry);
    for (auto& im : L.imports) ds_engine_add_import(e, im.iat_rva, im.name.c_str());
    for (uint64_t r : only) ds_engine_add_entry(e, r);

    if (ds_engine_disassemble(e) || ds_engine_build_cfg(e) ||
        ds_engine_resolve_symbols(e) || ds_engine_build_xrefs(e)) {
        fprintf(stderr, "analysis failed\n"); return 1;
    }

    // ---- read all instructions once (shared, read-only) ----
    size_t icount = ds_instruction_count(e);
    std::vector<ds_insn> insns(icount);
    if (icount) ds_disasm_range(e, 0, icount, insns.data());

    // ---- function list ----
    size_t fcount = ds_function_count(e);
    std::vector<ds_func> funcs(fcount);
    ds_get_functions(e, funcs.data(), fcount);

    // filter to the work list
    std::vector<size_t> work;
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (!only.empty()) { if (std::find(only.begin(), only.end(), funcs[i].rva) != only.end()) work.push_back(i); }
        else if (work.size() < cap) work.push_back(i);
    }

    CreateDirectoryA(outdir.c_str(), nullptr);

    // ---- N worker threads, each owns func indices [tid::N] ----
    std::atomic<size_t> written{0};
    auto worker = [&](int tid) {
        char path[1024];
        for (size_t wi = tid; wi < work.size(); wi += nthreads) {
            const ds_func& f = funcs[work[wi]];
            char* code = ds_decompile(e, f.rva);          // THREAD-SAFE: read-only on e
            if (!code) continue;
            std::string dec = code; ds_free_string(code);
            // trim check
            size_t a = dec.find_first_not_of(" \t\r\n");
            if (a == std::string::npos) continue;

            uint64_t end = f.rva + (f.size ? f.size : 1);
            std::string out;
            char hdr[256];
            snprintf(hdr, sizeof(hdr), "=== fun_%08llx @ %#llx size=%llu blocks=%u calls=%u ===\n--- DISASM ---\n",
                     (unsigned long long)f.rva, (unsigned long long)f.rva, (unsigned long long)f.size,
                     f.block_count, f.call_count);
            out = hdr;
            // disasm slice: binary-search the first insn >= f.rva, walk to end
            size_t lo = 0, hi = insns.size();
            while (lo < hi) { size_t m = (lo + hi) / 2; if (insns[m].rva < f.rva) lo = m + 1; else hi = m; }
            char line[160];
            for (size_t k = lo; k < insns.size() && insns[k].rva < end; ++k) {
                snprintf(line, sizeof(line), "  %#llx: %-9s %s\n",
                         (unsigned long long)insns[k].rva, insns[k].mnemonic, insns[k].operands);
                out += line;
            }
            out += "--- DECOMPILED ---\n";
            out += dec;
            out += "\n";

            snprintf(path, sizeof(path), "%s\\fn_%08llx.txt", outdir.c_str(), (unsigned long long)f.rva);
            FILE* of = fopen(path, "wb");
            if (of) { fwrite(out.data(), 1, out.size(), of); fclose(of); written.fetch_add(1); }
        }
    };

    DWORD t0 = GetTickCount();
    std::vector<std::thread> pool;
    for (int t = 0; t < nthreads; ++t) pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();

    printf("DUMPED %zu functions with %d threads in %lu ms -> %s\n",
           written.load(), nthreads, (unsigned long)(GetTickCount() - t0), outdir.c_str());
    ds_engine_destroy(e);
    return 0;
}
