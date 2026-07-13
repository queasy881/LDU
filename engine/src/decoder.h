/*
 * decoder.h — built-in x86 / x86-64 length + semantic decoder.
 *
 * The decoder fills the textual + reference fields of a single ds_insn from a
 * byte buffer. It never reads past `max_len` and always returns a forward
 * progress of at least 1 byte (emitting a "db" pseudo-instruction for bytes it
 * cannot decode) so a linear sweep can never stall.
 */
#ifndef DS_DECODER_H
#define DS_DECODER_H

#include <stdint.h>
#include <stddef.h>
#include "disasm.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode one instruction.
 *   bytes   : pointer to the first opcode byte
 *   max_len : number of valid bytes available at `bytes`
 *   addr    : the rva of this instruction (used to resolve relative targets)
 *   is64    : 1 for x86-64, 0 for x86-32
 *   out     : filled with rva,bytes,size,mnemonic,operands,ref_type,ref_target
 *
 * Returns the instruction length in bytes (1..15, never 0, never > max_len).
 * On undecodable input it sets mnemonic="db" and returns 1.
 */
uint8_t ds_decode(const uint8_t* bytes, size_t max_len, uint64_t addr,
                  int is64, ds_insn* out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DS_DECODER_H */
