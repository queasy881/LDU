/*
 * disasm.h — DisasmStudio engine C ABI (the single source of truth for the FFI boundary).
 *
 * Implemented by engine/src (C core) + engine/analysis (C++).
 * Consumed by crates/bridge via bindgen.
 *
 * Rules:
 *   - Plain C, fixed-width types, extern "C". No C++ types cross this boundary.
 *   - The engine never owns the image memory; the caller (Rust) keeps it alive
 *     for the whole engine lifetime.
 *   - No function here may abort/throw across the boundary; errors are int codes.
 */
#ifndef DISASM_H
#define DISASM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- enums ---------------------------------------------------------------- */

typedef enum {
    DS_ARCH_X86   = 0,
    DS_ARCH_X64   = 1,
    DS_ARCH_ARM   = 2,
    DS_ARCH_ARM64 = 3
} ds_arch;

/* ref_type values for ds_insn.ref_type */
enum {
    DS_REF_NONE   = 0,
    DS_REF_CALL   = 1,
    DS_REF_JMP    = 2,   /* unconditional jump */
    DS_REF_DATA   = 3,   /* memory/data reference */
    DS_REF_BRANCH = 4    /* conditional branch (jcc) */
};

/* segment permission flag bits for ds_segment.flags */
enum {
    DS_FLAG_R = 1u,
    DS_FLAG_W = 2u,
    DS_FLAG_X = 4u
};

/* xref kind for ds_xref.kind (matches DS_REF_* call/jmp/data) */
enum {
    DS_XREF_CALL = 1,
    DS_XREF_JMP  = 2,
    DS_XREF_DATA = 3
};

/* ---- POD records (flat, FFI-stable) -------------------------------------- */

typedef struct {
    char     name[32];
    uint64_t rva;
    uint64_t size;
    uint32_t flags;     /* DS_FLAG_R|W|X */
    uint32_t _pad;
} ds_segment;

typedef struct {
    uint64_t rva;
    uint8_t  bytes[16];
    uint8_t  size;       /* instruction length, 1..15 */
    uint8_t  ref_type;   /* DS_REF_* */
    uint8_t  _pad[6];
    uint64_t ref_target; /* referenced address, or 0 when ref_type==DS_REF_NONE */
    char     mnemonic[16];
    char     operands[80];
} ds_insn;

typedef struct {
    uint64_t rva;
    uint64_t size;
    uint32_t block_count;
    uint32_t call_count;
    char     name[96];
} ds_func;

typedef struct {
    uint64_t from_rva;
    uint64_t to_rva;
    uint32_t kind;       /* DS_XREF_* */
    uint32_t _pad;
} ds_xref;

typedef struct {
    ds_arch  arch;
    uint64_t base;
    uint64_t entry;
    uint64_t image_size;
    size_t   segment_count;
    size_t   function_count;
    size_t   instruction_count;
} ds_meta;

/* opaque engine handle */
typedef struct ds_engine ds_engine;

/* ---- lifecycle ------------------------------------------------------------ */

/* image/image_size: flat image laid out at RVAs (built by the Rust parser).
 * The pointer must stay valid until ds_engine_destroy. Returns NULL on OOM. */
ds_engine* ds_engine_create(const uint8_t* image, size_t image_size,
                            uint64_t base, ds_arch arch);
void       ds_engine_destroy(ds_engine* e);

/* ---- seeding (call before analysis) -------------------------------------- */

void ds_engine_add_segment(ds_engine* e, const char* name,
                           uint64_t rva, uint64_t size, uint32_t flags);
/* seed a known symbol name for an rva (from exports / debug info). This is the
 * highest-priority name source for a function start. */
void ds_engine_add_symbol(ds_engine* e, uint64_t rva, const char* name);
/* recover C++ class/virtual-function names from MSVC x64 RTTI and seed them as
 * symbols. Runs inside ds_engine_resolve_symbols before naming; x64-only, gated
 * by DS_NO_RTTI. Idempotent-safe: only seeds still-unnamed recovered functions. */
void ds_engine_scan_rtti(ds_engine* e);
/* recover real function names from the PDB named by the PE debug directory's
 * CodeView RSDS record, and seed them as symbols. Runs at build_cfg start,
 * before scan_rtti, so the PDB name wins. Windows-only (dbghelp), gated by
 * DS_NO_PDB. Idempotent-safe: never overwrites an already-seeded rva. */
void ds_engine_load_pdb(ds_engine* e);
/* seed a known function entry (entry point, export target, TLS callback) */
void ds_engine_add_entry(ds_engine* e, uint64_t rva);
/* seed an import: `name` is bound to the IAT slot rva that call/jmp thunks
 * dereference. Used to name forwarding thunks (j_<name>) and call sites. */
void ds_engine_add_import(ds_engine* e, uint64_t iat_rva, const char* name);
/* mark the binary as a DLL (1) or EXE (0). Affects entry-point naming:
 * DLL entry -> "DllMain", EXE entry -> "start". Default is EXE. */
void ds_engine_set_is_dll(ds_engine* e, int is_dll);
/* mark the entry rva explicitly (also added as an entry). Named per is_dll. */
void ds_engine_set_entry_rva(ds_engine* e, uint64_t rva);

/* ---- analysis stages (run in order; each returns 0 on success) ----------- */

int ds_engine_disassemble(ds_engine* e);      /* linear+recursive sweep      */
int ds_engine_build_cfg(ds_engine* e);        /* function & basic-block recovery */
int ds_engine_resolve_symbols(ds_engine* e);  /* name resolution priority chain  */
int ds_engine_build_xrefs(ds_engine* e);      /* bidirectional xref index     */
/* convenience: runs all four stages in order */
int ds_engine_analyze(ds_engine* e);

/* ---- user annotations (renames/comments that survive re-analysis) --------- */

/* Load/save the sidecar. Annotations are keyed by a content hash of the function
 * (rva as fallback), so they re-attach across a rebuild that moves code around.
 * Load REPLACES the in-memory store and is best called after ds_engine_build_cfg;
 * ds_engine_resolve_symbols re-binds and applies whatever is loaded. Setting
 * DS_ANNO_FILE=<path> makes resolve_symbols load it with no other wiring.
 * Both return 0 on success, 1 on I/O failure, 2 on a malformed file. */
int ds_engine_load_annotations(ds_engine* e, const char* path);
int ds_engine_save_annotations(ds_engine* e, const char* path);
/* Annotate the function at `rva` (upsert). NULL/"" leaves that field unchanged;
 * the stable identity hash is captured here, so call after ds_engine_build_cfg. */
void ds_engine_set_func_annotation(ds_engine* e, uint64_t rva, const char* name,
                                   const char* comment);
/* Rename a DISPLAY variable of the function at `rva`: `from` is the identifier as
 * the decompiler printed it (v3, result). Pure display alias, zero semantics. */
void ds_engine_set_var_annotation(ds_engine* e, uint64_t rva, const char* from,
                                  const char* to);

/* ---- queries -------------------------------------------------------------- */

void   ds_engine_get_meta(ds_engine* e, ds_meta* out);

size_t ds_segment_count(ds_engine* e);
size_t ds_get_segments(ds_engine* e, ds_segment* out, size_t max);

size_t ds_function_count(ds_engine* e);
size_t ds_get_functions(ds_engine* e, ds_func* out, size_t max);

size_t ds_instruction_count(ds_engine* e);
/* slice the linear listing by instruction INDEX; returns number written */
size_t ds_disasm_range(ds_engine* e, size_t start_index, size_t count, ds_insn* out);
/* map an rva to the index of the instruction at-or-after it; SIZE_MAX if none */
size_t ds_index_for_rva(ds_engine* e, uint64_t rva);

size_t ds_xrefs_to_count(ds_engine* e, uint64_t rva);
size_t ds_get_xrefs_to(ds_engine* e, uint64_t rva, ds_xref* out, size_t max);

/* ---- decompilation -------------------------------------------------------- */
/* Decompile the function at func_rva to pseudo-C. Returns a malloc'd, NUL-
 * terminated string the caller must free with ds_free_string, or NULL if the
 * rva is not a known function. */
char* ds_decompile(ds_engine* e, uint64_t func_rva);
void  ds_free_string(char* s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DISASM_H */
