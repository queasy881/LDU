/*
 * cs_decode.c — capstone decode front-end (see cs_decode.h).
 *
 * Compiled into the engine always, but only does real work when DS_USE_CAPSTONE
 * is defined (capstone headers/lib present). Otherwise the functions are no-op
 * stubs and the sweep uses the built-in decoder.
 */
#include "cs_decode.h"

#include <string.h>
#include <stdio.h>

#ifdef DS_USE_CAPSTONE

#include <capstone/capstone.h>

typedef struct {
    csh      h;
    cs_insn* insn; /* reused across cs_disasm_iter calls */
    int      arch; /* ds_arch: which operand union the detail lives in */
} ds_cs;

/* `arch` is a ds_arch ordinal (X86=0, X64=1, ARM=2, ARM64=3). It used to be
 * hardcoded to CS_ARCH_X86, so an AArch64 image was decoded as x86 and produced
 * a listing of plausible-looking garbage rather than an honest failure. */
void* ds_cs_open_arch(int arch, int is64) {
    ds_cs* c = (ds_cs*)malloc(sizeof(ds_cs));
    cs_arch  cs_a;
    cs_mode  mode;
    if (!c) return NULL;
    switch (arch) {
        case 3:  cs_a = CS_ARCH_ARM64; mode = CS_MODE_ARM;   break;
        case 2:  cs_a = CS_ARCH_ARM;   mode = CS_MODE_ARM;   break;
        default: cs_a = CS_ARCH_X86;   mode = is64 ? CS_MODE_64 : CS_MODE_32; break;
    }
    c->arch = arch;
    if (cs_open(cs_a, mode, &c->h) != CS_ERR_OK) {
        free(c);
        return NULL;
    }
    cs_option(c->h, CS_OPT_DETAIL, CS_OPT_ON);
    if (cs_a == CS_ARCH_X86) cs_option(c->h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    c->insn = cs_malloc(c->h);
    if (!c->insn) {
        cs_close(&c->h);
        free(c);
        return NULL;
    }
    return c;
}

void* ds_cs_open(int is64) { return ds_cs_open_arch(is64 ? 1 : 0, is64); }

void ds_cs_close(void* dec) {
    ds_cs* c = (ds_cs*)dec;
    if (!c) return;
    if (c->insn) cs_free(c->insn, 1);
    cs_close(&c->h);
    free(c);
}

/* Emit a single "db 0xNN" pseudo-instruction. */
static uint8_t emit_db(const uint8_t* bytes, uint64_t addr, ds_insn* out) {
    memset(out, 0, sizeof(*out));
    out->rva = addr;
    out->size = 1;
    out->bytes[0] = bytes[0];
    out->ref_type = DS_REF_NONE;
    out->ref_target = 0;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "db");
    snprintf(out->operands, sizeof(out->operands), "0x%02x", bytes[0]);
    return 1;
}

/* If op_str contains a "[rip + 0x..]" / "[rip - 0x..]" memory reference, rewrite
 * it to the absolute "[0x<abs>]" so the operand both reads cleanly and is
 * click-to-navigate in the UI. Operates in place within `cap`. */
static void rewrite_rip(char* op, size_t cap, uint64_t abs_addr) {
    char* lb = strstr(op, "[rip");
    if (!lb) return;
    char* rb = strchr(lb, ']');
    if (!rb) return;
    char tail[96];
    snprintf(tail, sizeof(tail), "%s", rb + 1); /* everything after ']' */
    /* lb points at '['; write "[0x<abs>]" + tail */
    size_t prefix = (size_t)(lb - op); /* keep text before '[' */
    if (prefix >= cap) return;
    snprintf(lb, cap - prefix, "[0x%llx]%s", (unsigned long long)abs_addr, tail);
}

uint8_t ds_cs_decode(void* dec, const uint8_t* bytes, size_t max_len,
                     uint64_t addr, int is64, ds_insn* out) {
    (void)is64;
    ds_cs* c = (ds_cs*)dec;
    if (!c || max_len == 0) {
        return emit_db(bytes, addr, out);
    }

    const uint8_t* code = bytes;
    size_t size = max_len;
    uint64_t address = addr;

    if (!cs_disasm_iter(c->h, &code, &size, &address, c->insn)) {
        return emit_db(bytes, addr, out);
    }

    cs_insn* in = c->insn;
    uint8_t len = (uint8_t)(in->size ? in->size : 1);

    memset(out, 0, sizeof(*out));
    out->rva = addr;
    out->size = len;
    {
        uint8_t n = len <= 16 ? len : 16;
        memcpy(out->bytes, bytes, n);
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", in->mnemonic);
    snprintf(out->operands, sizeof(out->operands), "%s", in->op_str);

    /* ---- reference extraction via instruction detail ---- */
    out->ref_type = DS_REF_NONE;
    out->ref_target = 0;

    cs_detail* d = in->detail;
    /* AArch64: the branch GROUPS are arch-neutral, but the operand union is not,
     * so the immediate has to be read out of d->arm64. Direct branches are all
     * PC-relative and capstone has already resolved them to an absolute address
     * in our rva space. An indirect `br`/`blr` has no static target, which is
     * reported honestly as no reference rather than guessed. */
    if (d && c->arch == 3) {
        cs_arm64* a = &d->arm64;
        int is_call = cs_insn_group(c->h, in, CS_GRP_CALL);
        int is_jump = cs_insn_group(c->h, in, CS_GRP_JUMP);
        if (is_call || is_jump) {
            int i;
            for (i = 0; i < a->op_count; i++) {
                if (a->operands[i].type == ARM64_OP_IMM) {
                    out->ref_target = (uint64_t)a->operands[i].imm;
                    /* `b` is the only unconditional plain jump; b.cond / cbz /
                     * cbnz / tbz / tbnz all fall through when not taken. */
                    out->ref_type = is_call ? DS_REF_CALL
                                            : (in->id == ARM64_INS_B && a->cc == ARM64_CC_AL
                                                   ? DS_REF_JMP
                                                   : DS_REF_BRANCH);
                    break;
                }
            }
        }
        return len;
    }
    if (d) {
        cs_x86* x = &d->x86;
        int is_call = cs_insn_group(c->h, in, CS_GRP_CALL);
        int is_jump = cs_insn_group(c->h, in, CS_GRP_JUMP);
        int is_ret = cs_insn_group(c->h, in, CS_GRP_RET);
        (void)is_ret;

        if (is_call || is_jump) {
            /* direct relative target = immediate operand (capstone resolves it
             * to an absolute address in our rva space since we pass addr). */
            int found = 0;
            for (int i = 0; i < x->op_count; i++) {
                if (x->operands[i].type == X86_OP_IMM) {
                    out->ref_target = (uint64_t)x->operands[i].imm;
                    out->ref_type = is_call
                        ? DS_REF_CALL
                        : (in->id == X86_INS_JMP ? DS_REF_JMP : DS_REF_BRANCH);
                    found = 1;
                    break;
                }
            }
            /* indirect through memory: call/jmp qword ptr [rip+x] (e.g. an IAT
             * thunk). Record the pointer slot as the target so imports get xrefs. */
            if (!found) {
                for (int i = 0; i < x->op_count; i++) {
                    if (x->operands[i].type == X86_OP_MEM) {
                        x86_op_mem* m = &x->operands[i].mem;
                        uint64_t t = 0;
                        if (m->base == X86_REG_RIP) {
                            t = in->address + in->size + (uint64_t)m->disp;
                        } else if (m->base == X86_REG_INVALID &&
                                   m->index == X86_REG_INVALID) {
                            t = (uint64_t)m->disp;
                        }
                        if (t) {
                            out->ref_target = t;
                            out->ref_type = is_call ? DS_REF_CALL : DS_REF_JMP;
                            rewrite_rip(out->operands, sizeof(out->operands), t);
                        }
                        break;
                    }
                }
            }
        } else {
            /* data reference: a rip-relative or absolute memory operand on a
             * non-branch instruction (lea/mov/etc.). */
            for (int i = 0; i < x->op_count; i++) {
                if (x->operands[i].type == X86_OP_MEM) {
                    x86_op_mem* m = &x->operands[i].mem;
                    uint64_t t = 0;
                    if (m->base == X86_REG_RIP) {
                        t = in->address + in->size + (uint64_t)m->disp;
                    } else if (m->base == X86_REG_INVALID &&
                               m->index == X86_REG_INVALID && m->disp != 0) {
                        t = (uint64_t)m->disp;
                    }
                    if (t) {
                        out->ref_target = t;
                        out->ref_type = DS_REF_DATA;
                        rewrite_rip(out->operands, sizeof(out->operands), t);
                    }
                    break;
                }
            }
        }
    }

    return len;
}

#else /* !DS_USE_CAPSTONE — stubs (sweep uses the built-in decoder) */

void* ds_cs_open_arch(int arch, int is64) { (void)arch; (void)is64; return NULL; }
void* ds_cs_open(int is64) { (void)is64; return NULL; }
void ds_cs_close(void* dec) { (void)dec; }
uint8_t ds_cs_decode(void* dec, const uint8_t* bytes, size_t max_len,
                     uint64_t addr, int is64, ds_insn* out) {
    (void)dec; (void)max_len; (void)is64;
    memset(out, 0, sizeof(*out));
    out->rva = addr;
    out->size = 1;
    out->bytes[0] = bytes[0];
    snprintf(out->mnemonic, sizeof(out->mnemonic), "db");
    snprintf(out->operands, sizeof(out->operands), "0x%02x", bytes[0]);
    return 1;
}

#endif /* DS_USE_CAPSTONE */
