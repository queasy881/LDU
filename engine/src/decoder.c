/*
 * decoder.c — built-in x86 / x86-64 length + semantic decoder.
 *
 * Goals (in order):
 *   1. Always make forward progress and never read past max_len.
 *   2. Compute a correct instruction length for the common encodings so a
 *      linear sweep stays aligned.
 *   3. Produce readable Intel-ish text + control-flow/data ref targets for the
 *      opcodes the analysis passes care about.
 *
 * This is intentionally a pragmatic, hand-rolled decoder: it covers the bulk of
 * real compiler-emitted code (MSVC/Clang x64 prologues, calls, jumps, moves,
 * ALU ops, lea, the 0F two-byte staples) precisely, and falls back to a correct
 * *length* with a generic mnemonic for the long tail. Anything it genuinely
 * cannot size is emitted as a 1-byte "db" so the sweep resynchronizes.
 */
#include "decoder.h"

#include <string.h>
#include <stdio.h>

/* ---- small helpers -------------------------------------------------------- */

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24));
}
static uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* signed-extended hex formatting: "+0x10" / "-0x18" / "0x401000" */
static void fmt_disp(char* dst, size_t cap, int64_t v) {
    if (v < 0) snprintf(dst, cap, "-0x%llx", (unsigned long long)(-v));
    else       snprintf(dst, cap, "+0x%llx", (unsigned long long)v);
}

/* register name tables, indexed by (size_log2, reg 0..15) */
static const char* REG8[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};
/* legacy 8-bit (no REX): ah/ch/dh/bh for 4..7 */
static const char* REG8L[8] = { "al","cl","dl","bl","ah","ch","dh","bh" };
static const char* REG16[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char* REG32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char* REG64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

/* opsize: 1,2,4,8 -> the right table */
static const char* regname(int opsize, int reg, int have_rex) {
    if (reg < 0) reg = 0;
    reg &= 0xF;
    switch (opsize) {
        case 1: return (have_rex ? REG8[reg] : (reg < 8 ? REG8L[reg] : REG8[reg]));
        case 2: return REG16[reg];
        case 8: return REG64[reg];
        default: return REG32[reg];
    }
}

static const char* sizeptr(int opsize) {
    switch (opsize) {
        case 1: return "byte ptr ";
        case 2: return "word ptr ";
        case 8: return "qword ptr ";
        case 16: return "xmmword ptr ";
        default: return "dword ptr ";
    }
}

/* xmm register names indexed 0..15 */
static const char* XMM[16] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
};
static const char* xmmname(int idx) {
    if (idx < 0) idx = 0;
    return XMM[idx & 0xF];
}

/* Is op2 (the byte after 0F) one of the SSE/SSE2 opcodes we decode here?
   Excludes 0F bytes already handled earlier (jcc/setcc/cmov/movzx/etc.). */
static int is_sse_opcode(uint8_t op2) {
    switch (op2) {
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x14: case 0x15: case 0x16: case 0x17:
        case 0x28: case 0x29: case 0x2A: case 0x2C:
        case 0x2D: case 0x2E: case 0x2F:
        case 0x51: case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x60: case 0x61: case 0x62: case 0x63:
        case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6A: case 0x6B:
        case 0x6E: case 0x6F:
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76:
        case 0x7E: case 0x7F:
        case 0xC6:
        case 0xD4: case 0xD6:
        case 0xDB: case 0xDF:
        case 0xEB: case 0xEF:
        case 0xF8: case 0xF9: case 0xFA: case 0xFB:
        case 0xFC: case 0xFD: case 0xFE:
            return 1;
        default:
            return 0;
    }
}

/* decode state for one instruction */
typedef struct {
    const uint8_t* p;     /* opcode cursor (after prefixes) */
    size_t         avail; /* bytes remaining at p */
    uint64_t       addr;
    int            is64;
    /* prefixes */
    int  rex, rex_w, rex_r, rex_x, rex_b;
    int  have_rex;
    int  opsz66;          /* 0x66 operand-size override */
    int  adsz67;          /* 0x67 address-size override */
    int  rep;             /* F3 */
    int  repne;           /* F2 */
    int  lock;            /* F0 */
    const char* seg;      /* segment override prefix or NULL */
    size_t prefix_len;    /* bytes consumed by prefixes */
    int  rm_is_xmm;       /* when set, a register r/m operand prints xmmN */
} dctx;

/* default operand size: 66 -> 2, REX.W -> 8, else 4 */
static int op_size(const dctx* c) {
    if (c->rex_w) return 8;
    if (c->opsz66) return 2;
    return 4;
}

/* ---- ModRM / SIB decoding ------------------------------------------------- */
/*
 * Decodes the ModRM (and SIB/disp) starting at c->p[off]. Writes the operand
 * text for the r/m operand into `rm` and the reg field into *reg_out.
 * Returns the number of bytes consumed from `off` (ModRM + SIB + disp), or
 * (size_t)-1 if it would read past the buffer.
 *
 * opsize selects the register-name table for the r/m when it is a register.
 * For a RIP-relative operand, *rip_target is set to the absolute resolved
 * address and *is_rip set to 1 (caller decides ref_type).
 */
static size_t decode_modrm(dctx* c, size_t off, int opsize,
                           char* rm, size_t rmcap, int* reg_out,
                           uint64_t insn_end_guess, /* unused for now */
                           int* is_rip, uint64_t* rip_disp) {
    (void)insn_end_guess;
    *is_rip = 0;
    *rip_disp = 0;
    if (off >= c->avail) return (size_t)-1;
    uint8_t modrm = c->p[off];
    int mod = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | (c->rex_r ? 8 : 0);
    int rm_field = (modrm & 7);
    int rm_ext = rm_field | (c->rex_b ? 8 : 0);
    *reg_out = reg;
    size_t used = 1; /* modrm */

    if (mod == 3) {
        /* direct register */
        if (c->rm_is_xmm)
            snprintf(rm, rmcap, "%s", xmmname(rm_ext));
        else
            snprintf(rm, rmcap, "%s", regname(opsize, rm_ext, c->have_rex));
        return used;
    }

    /* memory operand */
    int have_sib = (rm_field == 4);
    int base_reg = -1, index_reg = -1, scale = 1;
    int no_base = 0;
    int rip_rel = 0;

    if (have_sib) {
        if (off + used >= c->avail) return (size_t)-1;
        uint8_t sib = c->p[off + used];
        used++;
        scale = 1 << ((sib >> 6) & 3);
        int idx = ((sib >> 3) & 7) | (c->rex_x ? 8 : 0);
        int bas = (sib & 7) | (c->rex_b ? 8 : 0);
        if (((sib >> 3) & 7) == 4 && !c->rex_x) index_reg = -1; /* no index */
        else index_reg = idx;
        if ((sib & 7) == 5 && mod == 0) { no_base = 1; base_reg = -1; }
        else base_reg = bas;
    } else if (rm_field == 5 && mod == 0) {
        /* [RIP+disp32] in 64-bit, or [disp32] absolute in 32-bit */
        if (c->is64) rip_rel = 1;
        else no_base = 1;
    } else {
        base_reg = rm_ext;
    }

    /* displacement */
    int64_t disp = 0;
    int disp_bytes = 0;
    if (rip_rel) {
        disp_bytes = 4;
    } else if (mod == 1) {
        disp_bytes = 1;
    } else if (mod == 2) {
        disp_bytes = 4;
    } else if (mod == 0 && no_base) {
        disp_bytes = 4;
    }
    if (disp_bytes) {
        if (off + used + (size_t)disp_bytes > c->avail) return (size_t)-1;
        if (disp_bytes == 1) disp = (int8_t)c->p[off + used];
        else                 disp = (int32_t)rd32(c->p + off + used);
        used += disp_bytes;
    }

    /* format */
    const char* pfx = sizeptr(opsize);
    const char* segp = c->seg ? c->seg : "";
    const char* segc = c->seg ? ":" : "";
    if (rip_rel) {
        *is_rip = 1;
        *rip_disp = (uint64_t)disp; /* caller adds addr+size */
        snprintf(rm, rmcap, "%s%s%s[rip%s0x%llx]", pfx, segp, segc,
                 disp < 0 ? "-" : "+",
                 (unsigned long long)(disp < 0 ? -disp : disp));
        return used;
    }

    char inner[64];
    inner[0] = '\0';
    size_t ip = 0;
    int wrote = 0;
    if (base_reg >= 0) {
        ip += (size_t)snprintf(inner + ip, sizeof(inner) - ip, "%s",
                               regname(c->adsz67 ? 4 : (c->is64 ? 8 : 4), base_reg, c->have_rex));
        wrote = 1;
    }
    if (index_reg >= 0) {
        ip += (size_t)snprintf(inner + ip, sizeof(inner) - ip, "%s%s",
                               wrote ? "+" : "",
                               regname(c->adsz67 ? 4 : (c->is64 ? 8 : 4), index_reg, c->have_rex));
        if (scale > 1)
            ip += (size_t)snprintf(inner + ip, sizeof(inner) - ip, "*%d", scale);
        wrote = 1;
    }
    if (disp != 0 || !wrote) {
        char d[24];
        if (wrote) { fmt_disp(d, sizeof(d), disp); }
        else       { snprintf(d, sizeof(d), "0x%llx",
                              (unsigned long long)(uint32_t)disp); }
        ip += (size_t)snprintf(inner + ip, sizeof(inner) - ip, "%s", d);
    }
    snprintf(rm, rmcap, "%s%s%s[%s]", pfx, segp, segc, inner);
    return used;
}

/* ---- ALU op-name tables --------------------------------------------------- */
/* 00..3D primary ALU group, indexed by (opcode>>3)&7 */
static const char* ALU[8] = { "add","or","adc","sbb","and","sub","xor","cmp" };
/* 80/81/83 /digit -> same ordering */
/* shift group D0..D3,C0,C1 /digit */
static const char* SHIFT[8] = { "rol","ror","rcl","rcr","shl","shr","sal","sar" };
/* FF group /digit */
static const char* FFGRP[8] = { "inc","dec","call","callf","jmp","jmpf","push","?" };
/* F6/F7 group /digit */
static const char* F7GRP[8] = { "test","test","not","neg","mul","imul","div","idiv" };
/* jcc condition names for 70..7F and 0F 80..8F */
static const char* JCC[16] = {
    "jo","jno","jb","jae","je","jne","jbe","ja",
    "js","jns","jp","jnp","jl","jge","jle","jg"
};
static const char* SETCC[16] = {
    "seto","setno","setb","setae","sete","setne","setbe","seta",
    "sets","setns","setp","setnp","setl","setge","setle","setg"
};
static const char* CMOVCC[16] = {
    "cmovo","cmovno","cmovb","cmovae","cmove","cmovne","cmovbe","cmova",
    "cmovs","cmovns","cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg"
};

/* ---- main decode ---------------------------------------------------------- */

uint8_t ds_decode(const uint8_t* bytes, size_t max_len, uint64_t addr,
                  int is64, ds_insn* out) {
    /* clear output */
    memset(out, 0, sizeof(*out));
    out->rva = addr;
    out->ref_type = DS_REF_NONE;
    out->ref_target = 0;

    /* emit a 1-byte db pseudo-op (used for fallthrough on bad/empty input) */
    if (max_len == 0) {
        out->size = 1;
        out->bytes[0] = 0;
        memcpy(out->mnemonic, "db", 3);
        snprintf(out->operands, sizeof(out->operands), "0x00");
        return 1;
    }

    dctx c;
    memset(&c, 0, sizeof(c));
    c.addr = addr;
    c.is64 = is64;
    c.seg = NULL;

    /* ---- prefixes ---- */
    size_t i = 0;
    int more = 1;
    while (more && i < max_len) {
        uint8_t b = bytes[i];
        switch (b) {
            case 0x66: c.opsz66 = 1; i++; break;
            case 0x67: c.adsz67 = 1; i++; break;
            case 0xF0: c.lock = 1;   i++; break;
            case 0xF2: c.repne = 1;  i++; break;
            case 0xF3: c.rep = 1;    i++; break;
            case 0x2E: c.seg = "cs"; i++; break;
            case 0x36: c.seg = "ss"; i++; break;
            case 0x3E: c.seg = "ds"; i++; break;
            case 0x26: c.seg = "es"; i++; break;
            case 0x64: c.seg = "fs"; i++; break;
            case 0x65: c.seg = "gs"; i++; break;
            default: more = 0; break;
        }
    }
    /* REX (64-bit only), must be the last prefix before opcode */
    if (is64 && i < max_len && (bytes[i] & 0xF0) == 0x40) {
        c.rex = bytes[i];
        c.have_rex = 1;
        c.rex_w = (c.rex >> 3) & 1;
        c.rex_r = (c.rex >> 2) & 1;
        c.rex_x = (c.rex >> 1) & 1;
        c.rex_b = (c.rex) & 1;
        i++;
    }

    c.prefix_len = i;
    c.p = bytes + i;
    c.avail = max_len - i;

    /* helper to finalize: copies bytes, sets size, returns length */
    #define EMIT(len_) do {                                       \
        size_t L_ = (len_);                                       \
        if (L_ == 0) L_ = 1;                                      \
        if (L_ > max_len) L_ = max_len;                           \
        if (L_ > 15) L_ = 15;                                     \
        out->size = (uint8_t)L_;                                  \
        memcpy(out->bytes, bytes, L_);                            \
        return (uint8_t)L_;                                       \
    } while (0)

    /* fallback: a single db byte */
    #define DB1() do {                                            \
        out->size = 1; out->bytes[0] = bytes[0];                  \
        memcpy(out->mnemonic, "db", 3);                           \
        snprintf(out->operands, sizeof(out->operands),           \
                 "0x%02x", bytes[0]);                             \
        out->ref_type = DS_REF_NONE; out->ref_target = 0;         \
        return 1;                                                 \
    } while (0)

    if (c.avail == 0) DB1();

    uint8_t op = c.p[0];
    size_t opl = 1; /* opcode length within c.p, excludes operands */
    int opsize = op_size(&c);

    char rm[80], reg_s[16];
    int reg = 0, is_rip = 0;
    uint64_t rip_disp = 0;

    /* set mnemonic + operands buffers via locals to keep snprintf tidy */
    char mn[16]; mn[0] = '\0';
    char ops[80]; ops[0] = '\0';

    /* lambda-ish: finalize text + emit */
    #define SETTEXT(M, ...) do {                                  \
        snprintf(mn, sizeof(mn), "%s", (M));                      \
        snprintf(ops, sizeof(ops), __VA_ARGS__);                  \
    } while (0)

    #define DONE(total_) do {                                     \
        memcpy(out->mnemonic, mn, sizeof(out->mnemonic) < sizeof(mn) ? sizeof(out->mnemonic) : sizeof(mn)); \
        out->mnemonic[15] = '\0';                                 \
        snprintf(out->operands, sizeof(out->operands), "%s", ops);\
        EMIT(c.prefix_len + (total_));                            \
    } while (0)

    /* ============ two-byte 0F opcodes ============ */
    if (op == 0x0F) {
        if (c.avail < 2) DB1();
        uint8_t op2 = c.p[1];
        opl = 2;

        /* jcc rel32: 0F 80..8F */
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (c.avail < 6) DB1();
            int32_t rel = (int32_t)rd32(c.p + 2);
            uint64_t tgt = addr + (c.prefix_len + 6) + (uint64_t)(int64_t)rel;
            out->ref_type = DS_REF_BRANCH;
            out->ref_target = tgt;
            SETTEXT(JCC[op2 - 0x80], "0x%llx", (unsigned long long)tgt);
            DONE(6);
        }
        /* setcc r/m8: 0F 90..9F */
        if (op2 >= 0x90 && op2 <= 0x9F) {
            size_t m = decode_modrm(&c, 2, 1, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            SETTEXT(SETCC[op2 - 0x90], "%s", rm);
            DONE(2 + m);
        }
        /* cmovcc r,r/m: 0F 40..4F */
        if (op2 >= 0x40 && op2 <= 0x4F) {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            SETTEXT(CMOVCC[op2 - 0x40], "%s, %s", regname(opsize, reg, c.have_rex), rm);
            DONE(2 + m);
        }
        /* movzx/movsx: 0F B6 (zx8) B7 (zx16) BE (sx8) BF (sx16) */
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            int srcsz = (op2 == 0xB6 || op2 == 0xBE) ? 1 : 2;
            size_t m = decode_modrm(&c, 2, srcsz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            SETTEXT((op2 & 8) ? "movsx" : "movzx", "%s, %s", regname(opsize, reg, c.have_rex), rm);
            DONE(2 + m);
        }
        /* imul r,r/m: 0F AF */
        if (op2 == 0xAF) {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            SETTEXT("imul", "%s, %s", regname(opsize, reg, c.have_rex), rm);
            DONE(2 + m);
        }
        /* nop r/m (multi-byte nop): 0F 1F */
        if (op2 == 0x1F) {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            SETTEXT("nop", "%s", rm);
            DONE(2 + m);
        }
        /* syscall 0F 05, sysenter 0F 34, ud2 0F 0B, cpuid 0F A2, rdtsc 0F 31 */
        if (op2 == 0x05) { SETTEXT("syscall", "%s", ""); DONE(2); }
        if (op2 == 0x34) { SETTEXT("sysenter", "%s", ""); DONE(2); }
        if (op2 == 0x0B) { SETTEXT("ud2", "%s", ""); DONE(2); }
        if (op2 == 0xA2) { SETTEXT("cpuid", "%s", ""); DONE(2); }
        if (op2 == 0x31) { SETTEXT("rdtsc", "%s", ""); DONE(2); }
        if (op2 == 0x0D || op2 == 0x18 || op2 == 0x19) {
            /* prefetch / hint nop with modrm */
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            SETTEXT("nop", "%s", rm);
            DONE(2 + m);
        }
        /* ===== SSE / SSE2 packed & scalar ===== */
        /* mandatory-prefix selector: 0=none, 1=66, 2=F3, 3=F2 */
        if (is_sse_opcode(op2)) {
            int sel = c.opsz66 ? 1 : (c.rep ? 2 : (c.repne ? 3 : 0));
            const char* nm = NULL;   /* mnemonic; NULL -> "(bad)" w/ correct len */
            int dir = 0;             /* 0: reg<-rm (dst=reg), 1: rm<-reg (dst=rm) */
            int rm_xmm = 1;          /* r/m is an xmm/mem (vs GPR) */
            int rm_memsize = 16;     /* mem size when r/m is memory */
            int reg_xmm = 1;         /* reg field is xmm (vs GPR) */
            int has_ib = 0;          /* trailing imm8 */
            int is_group = 0;        /* 0F 71/72/73 shift-imm groups */

            switch (op2) {
            case 0x10: /* movups/movupd/movss/movsd  xmm, xmm/m */
                nm = (sel==1)?"movupd":(sel==2)?"movss":(sel==3)?"movsd":"movups";
                dir = 0; break;
            case 0x11: /* same, reversed */
                nm = (sel==1)?"movupd":(sel==2)?"movss":(sel==3)?"movsd":"movups";
                dir = 1; break;
            case 0x28: nm = (sel==1)?"movapd":"movaps"; dir = 0; break;
            case 0x29: nm = (sel==1)?"movapd":"movaps"; dir = 1; break;
            case 0x12: nm = (sel==1)?"movlpd":(sel==2)?"movsldup":(sel==3)?"movddup":"movlps"; dir = 0; break;
            case 0x13: nm = (sel==1)?"movlpd":"movlps"; dir = 1; break;
            case 0x14: nm = (sel==1)?"unpcklpd":"unpcklps"; dir = 0; break;
            case 0x15: nm = (sel==1)?"unpckhpd":"unpckhps"; dir = 0; break;
            case 0x16: nm = (sel==1)?"movhpd":(sel==2)?"movshdup":"movhps"; dir = 0; break;
            case 0x17: nm = (sel==1)?"movhpd":"movhps"; dir = 1; break;
            case 0x51: nm = (sel==1)?"sqrtpd":(sel==2)?"sqrtss":(sel==3)?"sqrtsd":"sqrtps"; dir = 0; break;
            case 0x54: nm = (sel==1)?"andpd":"andps"; dir = 0; break;
            case 0x55: nm = (sel==1)?"andnpd":"andnps"; dir = 0; break;
            case 0x56: nm = (sel==1)?"orpd":"orps"; dir = 0; break;
            case 0x57: nm = (sel==1)?"xorpd":"xorps"; dir = 0; break;
            case 0x58: nm = (sel==1)?"addpd":(sel==2)?"addss":(sel==3)?"addsd":"addps"; dir = 0; break;
            case 0x59: nm = (sel==1)?"mulpd":(sel==2)?"mulss":(sel==3)?"mulsd":"mulps"; dir = 0; break;
            case 0x5C: nm = (sel==1)?"subpd":(sel==2)?"subss":(sel==3)?"subsd":"subps"; dir = 0; break;
            case 0x5D: nm = (sel==1)?"minpd":(sel==2)?"minss":(sel==3)?"minsd":"minps"; dir = 0; break;
            case 0x5E: nm = (sel==1)?"divpd":(sel==2)?"divss":(sel==3)?"divsd":"divps"; dir = 0; break;
            case 0x5F: nm = (sel==1)?"maxpd":(sel==2)?"maxss":(sel==3)?"maxsd":"maxps"; dir = 0; break;
            case 0x5A: nm = (sel==1)?"cvtpd2ps":(sel==2)?"cvtss2sd":(sel==3)?"cvtsd2ss":"cvtps2pd"; dir = 0; break;
            case 0x5B: nm = (sel==1)?"cvtps2dq":(sel==2)?"cvttps2dq":"cvtdq2ps"; dir = 0; break;
            case 0x2A: /* cvtsi2ss/sd  xmm, r/m32-64 */
                nm = (sel==2)?"cvtsi2ss":(sel==3)?"cvtsi2sd":"cvtpi2ps";
                dir = 0; rm_xmm = 0; rm_memsize = c.rex_w ? 8 : 4; break;
            case 0x2C: /* cvttss2si/cvttsd2si  r32-64, xmm/m */
                nm = (sel==2)?"cvttss2si":(sel==3)?"cvttsd2si":"cvttps2pi";
                dir = 0; reg_xmm = 0; break;
            case 0x2D: /* cvtss2si/cvtsd2si  r32-64, xmm/m */
                nm = (sel==2)?"cvtss2si":(sel==3)?"cvtsd2si":"cvtps2pi";
                dir = 0; reg_xmm = 0; break;
            case 0x2E: nm = (sel==1)?"ucomisd":"ucomiss"; dir = 0; break;
            case 0x2F: nm = (sel==1)?"comisd":"comiss"; dir = 0; break;
            case 0x6E: /* movd/movq  xmm, r/m32-64 */
                nm = c.rex_w ? "movq" : "movd";
                dir = 0; rm_xmm = 0; rm_memsize = c.rex_w ? 8 : 4; break;
            case 0x7E:
                if (sel == 2) { /* F3 0F 7E movq xmm, xmm/m64 */
                    nm = "movq"; dir = 0; rm_xmm = 1; rm_memsize = 8;
                } else { /* movd/movq  r/m32-64, xmm */
                    nm = c.rex_w ? "movq" : "movd";
                    dir = 1; rm_xmm = 0; rm_memsize = c.rex_w ? 8 : 4;
                }
                break;
            case 0x6F: nm = (sel==2)?"movdqu":"movdqa"; dir = 0; break;
            case 0x7F: nm = (sel==2)?"movdqu":"movdqa"; dir = 1; break;
            case 0xD6: nm = "movq"; dir = 1; rm_xmm = 1; rm_memsize = 8; break;
            case 0xEF: nm = "pxor"; dir = 0; break;
            case 0xDB: nm = "pand"; dir = 0; break;
            case 0xDF: nm = "pandn"; dir = 0; break;
            case 0xEB: nm = "por"; dir = 0; break;
            case 0xFC: nm = "paddb"; dir = 0; break;
            case 0xFD: nm = "paddw"; dir = 0; break;
            case 0xFE: nm = "paddd"; dir = 0; break;
            case 0xD4: nm = "paddq"; dir = 0; break;
            case 0xF8: nm = "psubb"; dir = 0; break;
            case 0xF9: nm = "psubw"; dir = 0; break;
            case 0xFA: nm = "psubd"; dir = 0; break;
            case 0xFB: nm = "psubq"; dir = 0; break;
            case 0x60: nm = "punpcklbw"; dir = 0; break;
            case 0x61: nm = "punpcklwd"; dir = 0; break;
            case 0x62: nm = "punpckldq"; dir = 0; break;
            case 0x63: nm = "packsswb"; dir = 0; break;
            case 0x64: nm = "pcmpgtb"; dir = 0; break;
            case 0x65: nm = "pcmpgtw"; dir = 0; break;
            case 0x66: nm = "pcmpgtd"; dir = 0; break;
            case 0x67: nm = "packuswb"; dir = 0; break;
            case 0x68: nm = "punpckhbw"; dir = 0; break;
            case 0x69: nm = "punpckhwd"; dir = 0; break;
            case 0x6A: nm = "punpckhdq"; dir = 0; break;
            case 0x6B: nm = "packssdw"; dir = 0; break;
            case 0x74: nm = "pcmpeqb"; dir = 0; break;
            case 0x75: nm = "pcmpeqw"; dir = 0; break;
            case 0x76: nm = "pcmpeqd"; dir = 0; break;
            case 0xC6: nm = (sel==1)?"shufpd":"shufps"; dir = 0; has_ib = 1; break;
            case 0x70: nm = (sel==1)?"pshufd":(sel==2)?"pshufhw":(sel==3)?"pshuflw":"pshufw"; dir = 0; has_ib = 1; break;
            case 0x71: case 0x72: case 0x73:
                is_group = 1; has_ib = 1; break;
            default: nm = NULL; break;
            }

            if (is_group) {
                /* 0F 71/72/73 /digit ib : shift xmm by imm8.  The r/m is the
                   destination register (mod must be 3 in practice); reg field
                   selects the operation. */
                c.rm_is_xmm = 1;
                size_t m = decode_modrm(&c, 2, 16, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
                c.rm_is_xmm = 0;
                if (m == (size_t)-1) DB1();
                if (2 + m >= c.avail) DB1();
                uint8_t imm = c.p[2 + m];
                const char* gnm = NULL;
                int sub = reg & 7;
                if (op2 == 0x71) {
                    gnm = (sub==2)?"psrlw":(sub==4)?"psraw":(sub==6)?"psllw":NULL;
                } else if (op2 == 0x72) {
                    gnm = (sub==2)?"psrld":(sub==4)?"psrad":(sub==6)?"pslld":NULL;
                } else { /* 0x73 */
                    gnm = (sub==2)?"psrlq":(sub==3)?"psrldq":(sub==6)?"psllq":(sub==7)?"pslldq":NULL;
                }
                if (gnm) SETTEXT(gnm, "%s, 0x%x", rm, imm);
                else     SETTEXT("(bad)", "%s, 0x%x", rm, imm);
                DONE(2 + m + 1);
            }

            /* generic SSE form: reg field is xmm or GPR, r/m is xmm/mem or GPR/mem */
            c.rm_is_xmm = rm_xmm;
            {
                size_t m = decode_modrm(&c, 2, rm_memsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
                c.rm_is_xmm = 0;
                if (m == (size_t)-1) DB1();
                size_t total = 2 + m + (has_ib ? 1 : 0);
                if (has_ib && (2 + m) >= c.avail) DB1();
                if (is_rip) { uint64_t t = addr + (c.prefix_len + total) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
                const char* regtxt = reg_xmm ? xmmname(reg)
                                             : regname(c.rex_w ? 8 : 4, reg, c.have_rex);
                if (!nm) {
                    /* unknown SSE op: correct length, clean (bad) mnemonic */
                    if (dir) SETTEXT("(bad)", "%s, %s", rm, regtxt);
                    else     SETTEXT("(bad)", "%s, %s", regtxt, rm);
                } else if (has_ib) {
                    uint8_t imm = c.p[2 + m];
                    SETTEXT(nm, "%s, %s, 0x%x", regtxt, rm, imm);
                } else if (dir) {
                    SETTEXT(nm, "%s, %s", rm, regtxt);   /* dst = r/m */
                } else {
                    SETTEXT(nm, "%s, %s", regtxt, rm);   /* dst = reg */
                }
                DONE(total);
            }
        }
        /* bt/bts/btr/btc with imm8: 0F BA /digit ib (reg field selects op) */
        if (op2 == 0xBA) {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (2 + m >= c.avail) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m + 1) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            uint8_t imm = c.p[2 + m];
            static const char* BTGRP[8] = { "?","?","?","?","bt","bts","btr","btc" };
            SETTEXT(BTGRP[reg & 7], "%s, 0x%x", rm, imm);
            DONE(2 + m + 1);
        }
        /* bt/bts/btr/btc r/m,reg: 0F A3/AB/B3/BB.  bsf/bsr/popcnt r,r/m: BC/BD/B8 */
        if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB ||
            op2 == 0xBC || op2 == 0xBD || op2 == 0xB8) {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
                /* operand order is r/m, reg */
                const char* nm = (op2 == 0xA3) ? "bt" : (op2 == 0xAB) ? "bts"
                               : (op2 == 0xB3) ? "btr" : "btc";
                SETTEXT(nm, "%s, %s", rm, regname(opsize, reg, c.have_rex));
            } else {
                /* bsf/bsr/popcnt: reg, r/m */
                const char* nm = (op2 == 0xBC) ? (c.rep ? "tzcnt" : "bsf")
                               : (op2 == 0xBD) ? (c.rep ? "lzcnt" : "bsr") : "popcnt";
                SETTEXT(nm, "%s, %s", regname(opsize, reg, c.have_rex), rm);
            }
            DONE(2 + m);
        }
        /* xadd/cmpxchg: 0F C0/C1/B0/B1 (modrm) */
        if (op2 == 0xC0 || op2 == 0xC1 || op2 == 0xB0 || op2 == 0xB1) {
            int sz = (op2 == 0xC0 || op2 == 0xB0) ? 1 : opsize;
            size_t m = decode_modrm(&c, 2, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 2 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            SETTEXT((op2 & 0xF0) == 0xC0 ? "xadd" : "cmpxchg", "%s, %s", rm, regname(sz, reg, c.have_rex));
            DONE(2 + m);
        }

        /* generic 0F with modrm fallback (covers most remaining 2-byte ops) */
        {
            size_t m = decode_modrm(&c, 2, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            SETTEXT("(0f)", "0x%02x %s", op2, rm);
            DONE(2 + m);
        }
    }

    /* ============ one-byte opcodes ============ */

    /* ALU primary group 00..3D (8 ops x 6 forms) */
    if (op < 0x40 && (op & 0xC0) == 0x00 && (op & 7) < 6) {
        int g = (op >> 3) & 7;
        int form = op & 7; /* 0:Eb,Gb 1:Ev,Gv 2:Gb,Eb 3:Gv,Ev 4:AL,ib 5:eAX,iz */
        const char* name = ALU[g];
        if (form == 4) {
            if (c.avail < 2) DB1();
            uint8_t imm = c.p[1];
            SETTEXT(name, "al, 0x%x", imm);
            DONE(2);
        } else if (form == 5) {
            int isz = (opsize == 2) ? 2 : 4;
            if (c.avail < (size_t)(1 + isz)) DB1();
            uint32_t imm = (isz == 2) ? rd16(c.p + 1) : rd32(c.p + 1);
            SETTEXT(name, "%s, 0x%x", regname(opsize, 0, c.have_rex), imm);
            DONE(1 + isz);
        } else {
            int sz = (form & 1) ? opsize : 1;
            size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
            if (m == (size_t)-1) DB1();
            if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
            const char* rn = regname(sz, reg, c.have_rex);
            if (form < 2) SETTEXT(name, "%s, %s", rm, rn);   /* E, G */
            else          SETTEXT(name, "%s, %s", rn, rm);   /* G, E */
            DONE(1 + m);
        }
    }

    /* push/pop r 50..5F */
    if (op >= 0x50 && op <= 0x5F) {
        /* low 3 bits select the register; this range spans TWO opcodes
           (push 0x50-0x57, pop 0x58-0x5F), so mask rather than subtract a
           single base (op-0x50 would give r8..r15 for the pop half). */
        int r = (op & 7) | (c.rex_b ? 8 : 0);
        int sz = c.is64 ? 8 : (c.opsz66 ? 2 : 4);
        SETTEXT(op < 0x58 ? "push" : "pop", "%s", regname(sz, r, c.have_rex));
        DONE(1);
    }

    /* mov r, imm  B8+r (iz/io); B0+r imm8 */
    if (op >= 0xB8 && op <= 0xBF) {
        int r = (op - 0xB8) | (c.rex_b ? 8 : 0);
        if (c.rex_w) {
            if (c.avail < 9) DB1();
            uint64_t imm = rd64(c.p + 1);
            SETTEXT("movabs", "%s, 0x%llx", regname(8, r, c.have_rex), (unsigned long long)imm);
            DONE(9);
        } else {
            int isz = (opsize == 2) ? 2 : 4;
            if (c.avail < (size_t)(1 + isz)) DB1();
            uint32_t imm = (isz == 2) ? rd16(c.p + 1) : rd32(c.p + 1);
            SETTEXT("mov", "%s, 0x%x", regname(opsize, r, c.have_rex), imm);
            DONE(1 + isz);
        }
    }
    if (op >= 0xB0 && op <= 0xB7) {
        int r = (op - 0xB0) | (c.rex_b ? 8 : 0);
        if (c.avail < 2) DB1();
        SETTEXT("mov", "%s, 0x%x", regname(1, r, c.have_rex), c.p[1]);
        DONE(2);
    }

    /* mov r/m,r / r,r/m 88..8B */
    if (op >= 0x88 && op <= 0x8B) {
        int sz = (op & 1) ? opsize : 1;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        const char* rn = regname(sz, reg, c.have_rex);
        if (op < 0x8A) SETTEXT("mov", "%s, %s", rm, rn);
        else           SETTEXT("mov", "%s, %s", rn, rm);
        DONE(1 + m);
    }

    /* movsxd r64/r32, r/m32  (0x63 in 64-bit mode) */
    if (op == 0x63 && c.is64) {
        /* src is always a 32-bit r/m; dst is reg sized by REX.W (8) else 4 */
        size_t m = decode_modrm(&c, 1, 4, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT("movsxd", "%s, %s", regname(c.rex_w ? 8 : 4, reg, c.have_rex), rm);
        DONE(1 + m);
    }

    /* lea 8D (Gv, M) — RIP-relative => DATA ref */
    if (op == 0x8D) {
        size_t m = decode_modrm(&c, 1, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) {
            uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp;
            out->ref_type = DS_REF_DATA;
            out->ref_target = t;
            /* rewrite rm to show resolved target for readability */
            snprintf(rm, sizeof(rm), "[0x%llx]", (unsigned long long)t);
        }
        SETTEXT("lea", "%s, %s", regname(opsize, reg, c.have_rex), rm);
        DONE(1 + m);
    }

    /* test r/m,r 84/85 */
    if (op == 0x84 || op == 0x85) {
        int sz = (op & 1) ? opsize : 1;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT("test", "%s, %s", rm, regname(sz, reg, c.have_rex));
        DONE(1 + m);
    }
    /* test al/eax, imm A8/A9 */
    if (op == 0xA8) { if (c.avail < 2) DB1(); SETTEXT("test", "al, 0x%x", c.p[1]); DONE(2); }
    if (op == 0xA9) {
        int isz = (opsize == 2) ? 2 : 4;
        if (c.avail < (size_t)(1 + isz)) DB1();
        uint32_t imm = (isz == 2) ? rd16(c.p + 1) : rd32(c.p + 1);
        SETTEXT("test", "%s, 0x%x", regname(opsize, 0, c.have_rex), imm);
        DONE(1 + isz);
    }

    /* xchg r/m,r 86/87 */
    if (op == 0x86 || op == 0x87) {
        int sz = (op & 1) ? opsize : 1;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT("xchg", "%s, %s", rm, regname(sz, reg, c.have_rex));
        DONE(1 + m);
    }
    /* xchg eax,r 91..97 (90 is nop) */
    if (op >= 0x91 && op <= 0x97) {
        int r = (op - 0x90) | (c.rex_b ? 8 : 0);
        SETTEXT("xchg", "%s, %s", regname(opsize, 0, c.have_rex), regname(opsize, r, c.have_rex));
        DONE(1);
    }

    /* mov r/m, imm  C6 (ib) / C7 (iz) */
    if (op == 0xC6 || op == 0xC7) {
        int sz = (op == 0xC6) ? 1 : opsize;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        int isz = (op == 0xC6) ? 1 : ((opsize == 2) ? 2 : 4);
        if (1 + m + (size_t)isz > c.avail) DB1();
        uint32_t imm = (isz == 1) ? c.p[1 + m] : (isz == 2 ? rd16(c.p + 1 + m) : rd32(c.p + 1 + m));
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m + isz) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t;
                      snprintf(rm, sizeof(rm), "%s[0x%llx]", sizeptr(sz), (unsigned long long)t); }
        SETTEXT("mov", "%s, 0x%x", rm, imm);
        DONE(1 + m + isz);
    }

    /* immediate ALU group 80/81/83 /digit */
    if (op == 0x80 || op == 0x81 || op == 0x83) {
        int sz = (op == 0x80) ? 1 : opsize;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        int isz = (op == 0x81) ? ((opsize == 2) ? 2 : 4) : 1;
        if (1 + m + (size_t)isz > c.avail) DB1();
        int64_t imm;
        if (op == 0x83) imm = (int8_t)c.p[1 + m];
        else if (isz == 2) imm = (int16_t)rd16(c.p + 1 + m);
        else if (op == 0x80) imm = c.p[1 + m];
        else imm = (int32_t)rd32(c.p + 1 + m);
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m + isz) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT(ALU[reg & 7], "%s, 0x%llx", rm, (unsigned long long)(uint64_t)imm);
        DONE(1 + m + isz);
    }

    /* shift group C0/C1 (ib), D0/D1 (1), D2/D3 (cl) */
    if (op == 0xC0 || op == 0xC1 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3) {
        int sz = (op & 1) ? opsize : 1;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        const char* name = SHIFT[reg & 7];
        if (op == 0xC0 || op == 0xC1) {
            if (1 + m >= c.avail) DB1();
            SETTEXT(name, "%s, 0x%x", rm, c.p[1 + m]);
            DONE(1 + m + 1);
        } else if (op == 0xD0 || op == 0xD1) {
            SETTEXT(name, "%s, 1", rm);
            DONE(1 + m);
        } else {
            SETTEXT(name, "%s, cl", rm);
            DONE(1 + m);
        }
    }

    /* F6/F7 group (test/not/neg/mul/imul/div/idiv) */
    if (op == 0xF6 || op == 0xF7) {
        int sz = (op == 0xF6) ? 1 : opsize;
        size_t m = decode_modrm(&c, 1, sz, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        int g = reg & 7;
        if (g == 0 || g == 1) {
            int isz = (op == 0xF6) ? 1 : ((opsize == 2) ? 2 : 4);
            if (1 + m + (size_t)isz > c.avail) DB1();
            uint32_t imm = (isz == 1) ? c.p[1 + m] : (isz == 2 ? rd16(c.p + 1 + m) : rd32(c.p + 1 + m));
            SETTEXT("test", "%s, 0x%x", rm, imm);
            DONE(1 + m + isz);
        }
        SETTEXT(F7GRP[g], "%s", rm);
        DONE(1 + m);
    }

    /* inc/dec/call/jmp/push group FF /digit */
    if (op == 0xFF) {
        size_t m = decode_modrm(&c, 1, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        int g = reg & 7;
        if (is_rip) {
            uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp;
            out->ref_target = t;
            if (g == 2 || g == 3) out->ref_type = DS_REF_CALL;       /* call [rip] (IAT) */
            else if (g == 4 || g == 5) out->ref_type = DS_REF_JMP;   /* jmp  [rip] (thunk) */
            else out->ref_type = DS_REF_DATA;
            snprintf(rm, sizeof(rm), "%s[0x%llx]", sizeptr(c.is64 ? 8 : 4), (unsigned long long)t);
        }
        SETTEXT(FFGRP[g], "%s", rm);
        DONE(1 + m);
    }
    /* FE group inc/dec r/m8 */
    if (op == 0xFE) {
        size_t m = decode_modrm(&c, 1, 1, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        SETTEXT((reg & 7) ? "dec" : "inc", "%s", rm);
        DONE(1 + m);
    }

    /* 8F /0 pop r/m */
    if (op == 0x8F) {
        size_t m = decode_modrm(&c, 1, c.is64 ? 8 : opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        SETTEXT("pop", "%s", rm);
        DONE(1 + m);
    }

    /* call rel32 E8 */
    if (op == 0xE8) {
        if (c.avail < 5) DB1();
        int32_t rel = (int32_t)rd32(c.p + 1);
        uint64_t tgt = addr + (c.prefix_len + 5) + (uint64_t)(int64_t)rel;
        out->ref_type = DS_REF_CALL;
        out->ref_target = tgt;
        SETTEXT("call", "0x%llx", (unsigned long long)tgt);
        DONE(5);
    }
    /* jmp rel32 E9 */
    if (op == 0xE9) {
        if (c.avail < 5) DB1();
        int32_t rel = (int32_t)rd32(c.p + 1);
        uint64_t tgt = addr + (c.prefix_len + 5) + (uint64_t)(int64_t)rel;
        out->ref_type = DS_REF_JMP;
        out->ref_target = tgt;
        SETTEXT("jmp", "0x%llx", (unsigned long long)tgt);
        DONE(5);
    }
    /* jmp rel8 EB */
    if (op == 0xEB) {
        if (c.avail < 2) DB1();
        int8_t rel = (int8_t)c.p[1];
        uint64_t tgt = addr + (c.prefix_len + 2) + (uint64_t)(int64_t)rel;
        out->ref_type = DS_REF_JMP;
        out->ref_target = tgt;
        SETTEXT("jmp", "0x%llx", (unsigned long long)tgt);
        DONE(2);
    }
    /* jcc rel8 70..7F */
    if (op >= 0x70 && op <= 0x7F) {
        if (c.avail < 2) DB1();
        int8_t rel = (int8_t)c.p[1];
        uint64_t tgt = addr + (c.prefix_len + 2) + (uint64_t)(int64_t)rel;
        out->ref_type = DS_REF_BRANCH;
        out->ref_target = tgt;
        SETTEXT(JCC[op - 0x70], "0x%llx", (unsigned long long)tgt);
        DONE(2);
    }
    /* jcxz/loop E0..E3 rel8 */
    if (op >= 0xE0 && op <= 0xE3) {
        if (c.avail < 2) DB1();
        int8_t rel = (int8_t)c.p[1];
        uint64_t tgt = addr + (c.prefix_len + 2) + (uint64_t)(int64_t)rel;
        out->ref_type = DS_REF_BRANCH;
        out->ref_target = tgt;
        const char* nm = (op == 0xE0) ? "loopne" : (op == 0xE1) ? "loope" : (op == 0xE2) ? "loop" : "jrcxz";
        SETTEXT(nm, "0x%llx", (unsigned long long)tgt);
        DONE(2);
    }

    /* ret / retn imm16 */
    if (op == 0xC3) { SETTEXT("ret", "%s", ""); DONE(1); }
    if (op == 0xC2) {
        if (c.avail < 3) DB1();
        SETTEXT("ret", "0x%x", rd16(c.p + 1));
        DONE(3);
    }
    if (op == 0xCB) { SETTEXT("retf", "%s", ""); DONE(1); }
    if (op == 0xCA) { if (c.avail < 3) DB1(); SETTEXT("retf", "0x%x", rd16(c.p + 1)); DONE(3); }

    /* leave / nop / int3 / cdq family / hlt */
    if (op == 0xC9) { SETTEXT("leave", "%s", ""); DONE(1); }
    if (op == 0x90) { SETTEXT(c.rep ? "pause" : "nop", "%s", ""); DONE(1); }
    if (op == 0xCC) { SETTEXT("int3", "%s", ""); DONE(1); }
    if (op == 0xCD) { if (c.avail < 2) DB1(); SETTEXT("int", "0x%x", c.p[1]); DONE(2); }
    if (op == 0xF4) { SETTEXT("hlt", "%s", ""); DONE(1); }
    if (op == 0x98) { SETTEXT(c.rex_w ? "cdqe" : (c.opsz66 ? "cbw" : "cwde"), "%s", ""); DONE(1); }
    if (op == 0x99) { SETTEXT(c.rex_w ? "cqo" : (c.opsz66 ? "cwd" : "cdq"), "%s", ""); DONE(1); }
    if (op == 0xF5) { SETTEXT("cmc", "%s", ""); DONE(1); }
    if (op == 0xF8) { SETTEXT("clc", "%s", ""); DONE(1); }
    if (op == 0xF9) { SETTEXT("stc", "%s", ""); DONE(1); }
    if (op == 0xFC) { SETTEXT("cld", "%s", ""); DONE(1); }
    if (op == 0xFD) { SETTEXT("std", "%s", ""); DONE(1); }

    /* push imm32 68 / push imm8 6A */
    if (op == 0x68) {
        if (c.avail < 5) DB1();
        SETTEXT("push", "0x%x", rd32(c.p + 1));
        DONE(5);
    }
    if (op == 0x6A) {
        if (c.avail < 2) DB1();
        SETTEXT("push", "0x%llx", (unsigned long long)(int64_t)(int8_t)c.p[1]);
        DONE(2);
    }

    /* imul r,r/m,imm 69 (iz) / 6B (ib) */
    if (op == 0x69 || op == 0x6B) {
        size_t m = decode_modrm(&c, 1, opsize, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        int isz = (op == 0x6B) ? 1 : ((opsize == 2) ? 2 : 4);
        if (1 + m + (size_t)isz > c.avail) DB1();
        int64_t imm = (op == 0x6B) ? (int8_t)c.p[1 + m]
                    : (isz == 2 ? (int16_t)rd16(c.p + 1 + m) : (int32_t)rd32(c.p + 1 + m));
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m + isz) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT("imul", "%s, %s, 0x%llx", regname(opsize, reg, c.have_rex), rm, (unsigned long long)(uint64_t)imm);
        DONE(1 + m + isz);
    }

    /* mov AL/eAX <-> moffs A0..A3 (has address-size immediate) */
    if (op >= 0xA0 && op <= 0xA3) {
        int asz = c.is64 ? 8 : (c.adsz67 ? 2 : 4);
        if (1 + (size_t)asz > c.avail) DB1();
        uint64_t off = (asz == 8) ? rd64(c.p + 1) : (asz == 2 ? rd16(c.p + 1) : rd32(c.p + 1));
        int sz = (op & 1) ? opsize : 1;
        if (op <= 0xA1) SETTEXT("mov", "%s, [0x%llx]", regname(sz, 0, c.have_rex), (unsigned long long)off);
        else            SETTEXT("mov", "[0x%llx], %s", (unsigned long long)off, regname(sz, 0, c.have_rex));
        DONE(1 + asz);
    }

    /* string ops (single byte, no operands of interest) */
    if (op == 0xA4) { SETTEXT("movsb", "%s", ""); DONE(1); }
    if (op == 0xA5) { SETTEXT(c.rex_w ? "movsq" : (c.opsz66 ? "movsw" : "movsd"), "%s", ""); DONE(1); }
    if (op == 0xA6) { SETTEXT("cmpsb", "%s", ""); DONE(1); }
    if (op == 0xA7) { SETTEXT("cmpsd", "%s", ""); DONE(1); }
    if (op == 0xAA) { SETTEXT("stosb", "%s", ""); DONE(1); }
    if (op == 0xAB) { SETTEXT(c.rex_w ? "stosq" : (c.opsz66 ? "stosw" : "stosd"), "%s", ""); DONE(1); }
    if (op == 0xAC) { SETTEXT("lodsb", "%s", ""); DONE(1); }
    if (op == 0xAD) { SETTEXT(c.rex_w ? "lodsq" : "lodsd", "%s", ""); DONE(1); }
    if (op == 0xAE) { SETTEXT("scasb", "%s", ""); DONE(1); }
    if (op == 0xAF) { SETTEXT("scasd", "%s", ""); DONE(1); }

    /* inc/dec eax..edi 40..4F — only in 32-bit (in 64-bit these are REX, handled) */
    if (!c.is64 && op >= 0x40 && op <= 0x4F) {
        SETTEXT(op < 0x48 ? "inc" : "dec", "%s", REG32[op & 7]);
        DONE(1);
    }

    /* pushf/popf */
    if (op == 0x9C) { SETTEXT(c.is64 ? "pushfq" : "pushfd", "%s", ""); DONE(1); }
    if (op == 0x9D) { SETTEXT(c.is64 ? "popfq" : "popfd", "%s", ""); DONE(1); }
    if (op == 0x9B) { SETTEXT("wait", "%s", ""); DONE(1); }
    if (op == 0x9E) { SETTEXT("sahf", "%s", ""); DONE(1); }
    if (op == 0x9F) { SETTEXT("lahf", "%s", ""); DONE(1); }

    /* x87 / fpu D8..DF: have a modrm; size via modrm, generic mnemonic */
    if (op >= 0xD8 && op <= 0xDF) {
        size_t m = decode_modrm(&c, 1, 4, rm, sizeof(rm), &reg, 0, &is_rip, &rip_disp);
        if (m == (size_t)-1) DB1();
        if (is_rip) { uint64_t t = addr + (c.prefix_len + 1 + m) + rip_disp; out->ref_type = DS_REF_DATA; out->ref_target = t; }
        SETTEXT("fpu", "%s", rm);
        DONE(1 + m);
    }

    /* in/out with imm8 E4/E5/E6/E7 ; in/out dx EC..EF */
    if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) {
        if (c.avail < 2) DB1();
        SETTEXT((op & 2) ? "out" : "in", "0x%x", c.p[1]);
        DONE(2);
    }
    if (op >= 0xEC && op <= 0xEF) { SETTEXT((op & 2) ? "out" : "in", "dx"); DONE(1); }

    /* If we reach here it's an opcode we don't model; try to size it via modrm
       when the encoding clearly carries one, else fall back to a single db. The
       safe default keeps the sweep aligned for the common case where the byte
       is genuinely data. */
    DB1();
}
