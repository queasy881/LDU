/*
 * cs_decode.h — capstone-backed decode front-end.
 *
 * When the engine is built with DS_USE_CAPSTONE, the sweep decodes instructions
 * through capstone (the real x86/x64 disassembler) instead of the built-in
 * hand-rolled decoder. The handle is opened once per analysis run.
 */
#ifndef DS_CS_DECODE_H
#define DS_CS_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include "disasm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Open a capstone decode handle for `arch` (a ds_arch ordinal: X86=0, X64=1,
 * ARM=2, ARM64=3); `is64` selects the x86 mode. Returns an opaque pointer, or
 * NULL on failure (caller should fall back to the built-in decoder). */
void* ds_cs_open_arch(int arch, int is64);
/* x86-only shorthand, kept for callers that predate multi-arch support. */
void* ds_cs_open(int is64);

/* Close a handle from ds_cs_open. */
void ds_cs_close(void* dec);

/* Decode one instruction at `bytes` (rva `addr`) into `out`, filling
 * size/bytes/mnemonic/operands and ref_type/ref_target (call/jmp/branch targets
 * and rip-relative or absolute data references). Returns the instruction length
 * (>=1); emits a 1-byte "db" on undecodable input so the sweep resynchronizes. */
uint8_t ds_cs_decode(void* dec, const uint8_t* bytes, size_t max_len,
                     uint64_t addr, int is64, ds_insn* out);

#ifdef __cplusplus
}
#endif

#endif /* DS_CS_DECODE_H */
