/*
 * decompiler.cpp — Ghidra-quality pseudo-C decompiler for x86-64 (MSVC /Od).
 *
 * Pipeline (helper components, in order):
 *   1. Disassembler   : capstone cs_disasm over [rva, rva+size) with detail on.
 *   2. CfgBuilder     : leaders -> basic blocks -> succ/pred edges, plus
 *                       jump-table dispatch recovery (rip-relative .rdata table).
 *   3. Symbolic exec  : per-block forward symbolic execution over a value model
 *                       (reg->Expr, stackslot->Expr). Register writes only update
 *                       the map (no statement); a statement is emitted only when
 *                       writing a recovered variable (stack local / param / mem),
 *                       calling, or returning. This is what folds
 *                       `mov eax,[a]; add eax,[b]; mov [c],eax` to `c = a + b;`
 *                       with no eax anywhere in the output.
 *   4. Phi / temps    : registers live across a CFG join with differing values
 *                       get a materialized temp (t1..). Minimized via liveness.
 *   5. Dominators     : Cooper-Harvey-Kennedy dominators + post-dominators,
 *                       natural-loop / back-edge detection.
 *   6. Structurer     : recursive region structuring -> if/else, while, do-while,
 *                       for, switch; goto only for genuinely irreducible regions.
 *   7. Emitter        : pretty-printer respecting C precedence with minimal
 *                       parentheses/casts, recovered typed locals and params.
 *
 * Correctness over prettiness: arithmetic widths, comparison signedness, branch
 * directions and memory access sizes are preserved exactly. When a structuring
 * transform cannot be proven correct we emit a correct goto for THAT region only;
 * we never emit semantically wrong structure, and never emit a raw register name.
 *
 * The real work compiles only when DS_USE_CAPSTONE is defined. Without it we
 * still provide ds_decompile / ds_free_string so the TU always links.
 */

#include "decompiler.h"
#include "disasm.h"
#include "engine_internal.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <mutex>
#include <algorithm>
#include <memory>
#include <functional>
#include <array>
#include <chrono>

#ifdef DS_USE_CAPSTONE
#include <capstone/capstone.h>
#endif

/* ====================================================================== */
/*  malloc'd-string helper (shared by both build configurations)          */
/* ====================================================================== */

static char* dup_to_c(const std::string& s) {
    char* out = (char*)std::malloc(s.size() + 1);
    if (!out) return nullptr;
    std::memcpy(out, s.data(), s.size());
    out[s.size()] = '\0';
    return out;
}

extern "C" void ds_free_string(char* s) {
    if (s) std::free(s);
}

#ifndef DS_USE_CAPSTONE
/* ---------------------------------------------------------------------- */
/*  No capstone backend: emit a harmless stub so the engine still links.   */
/* ---------------------------------------------------------------------- */
extern "C" char* ds_decompile(ds_engine* e, uint64_t func_rva) {
    if (!e) return nullptr;
    const ds_func* f = nullptr;
    for (size_t i = 0; i < e->func_len; ++i)
        if (e->funcs[i].rva == func_rva) { f = &e->funcs[i]; break; }
    if (!f) return nullptr;
    std::string name = (f->name[0] ? std::string(f->name)
                                   : "sub_" + std::to_string(func_rva));
    std::string s = "/* decompilation unavailable: built without capstone */\n";
    s += "void " + name + "(void) {\n}\n";
    return dup_to_c(s);
}

#else /* DS_USE_CAPSTONE ================================================= */

namespace {

/* ====================================================================== */
/*  Small utilities                                                        */
/* ====================================================================== */

std::string hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

/* MSVC C++ name demangling via dbghelp!UnDecorateSymbolName, resolved at RUNTIME
 * (LoadLibrary/GetProcAddress — no link-time dependency, and the raw name simply
 * passes through when unavailable or on non-Windows). A mangled
 *   ?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
 * becomes `std::cout`, and
 *   ?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ
 * becomes `std::basic_ostream<char>::_Osfx`. sani()ing THAT yields a readable
 * identifier instead of sani()ing the mangled soup into
 * `__Osfx___basic_ostream_DU__char_traits_D_std___std__QEAAXXZ`.
 * UNDNAME_NAME_ONLY (0x1000) = qualified name only (no return type/params/CC).
 * Cached under a mutex: dumptool decompiles across N threads. DS_NO_DEMANGLE. */
#if defined(_WIN32)
extern "C" __declspec(dllimport) void* __stdcall LoadLibraryA(const char*);
extern "C" __declspec(dllimport) void* __stdcall GetProcAddress(void*, const char*);
#endif
/* Collapse the standard library's template spellings to the typedefs a human
 * actually reads — `std::basic_ostream<char,std::char_traits<char> >` is
 * `std::ostream` — and give operator symbols pronounceable names. Without this the
 * sani'd identifier is 60 characters of template soup
 * (`std__basic_ostream_char_std__char_traits_char_____operator__`); with it, it is
 * `std__ostream__operator_shl`. NOTE an infix `a << b` is NOT an option: the /TC
 * gate compiles C, where `void* << char*` is invalid — so the NAME carries the
 * meaning instead. */
static void simplify_std_name(std::string& s) {
    struct R { const char* from; const char* to; };
    static const R tbl[] = {
        /* longest / most specific first */
        {"basic_string<char,std::char_traits<char>,std::allocator<char> >", "string"},
        {"basic_string<char,std::char_traits<char>,std::allocator<char>>",  "string"},
        {"basic_iostream<char,std::char_traits<char> >", "iostream"},
        {"basic_iostream<char,std::char_traits<char>>",  "iostream"},
        {"basic_ostream<wchar_t,std::char_traits<wchar_t> >", "wostream"},
        {"basic_istream<wchar_t,std::char_traits<wchar_t> >", "wistream"},
        {"basic_ostream<char,std::char_traits<char> >", "ostream"},
        {"basic_ostream<char,std::char_traits<char>>",  "ostream"},
        {"basic_istream<char,std::char_traits<char> >", "istream"},
        {"basic_istream<char,std::char_traits<char>>",  "istream"},
        {"basic_streambuf<char,std::char_traits<char> >", "streambuf"},
        {"basic_streambuf<char,std::char_traits<char>>",  "streambuf"},
        {"basic_ios<char,std::char_traits<char> >", "ios"},
        {"basic_ios<char,std::char_traits<char>>",  "ios"},
        {"operator<<", "operator_shl"}, {"operator>>", "operator_shr"},
        {"operator==", "operator_eq"},  {"operator!=", "operator_ne"},
        {"operator<=", "operator_le"},  {"operator>=", "operator_ge"},
        {"operator[]", "operator_idx"}, {"operator()", "operator_call"},
        {"operator+=", "operator_addeq"}, {"operator-=", "operator_subeq"},
        {"operator new", "operator_new"}, {"operator delete", "operator_delete"},
        {"operator=", "operator_assign"},
    };
    for (const R& r : tbl) {
        size_t fl = std::strlen(r.from), tl = std::strlen(r.to), p = 0;
        while ((p = s.find(r.from, p)) != std::string::npos) { s.replace(p, fl, r.to); p += tl; }
    }
}

static std::string demangle_msvc(const std::string& mangled) {
    if (mangled.size() < 2 || mangled[0] != '?') return mangled;
#if defined(_WIN32)
    if (std::getenv("DS_NO_DEMANGLE")) return mangled;
    typedef unsigned long(__stdcall * UnDecFn)(const char*, char*, unsigned long, unsigned long);
    static std::mutex m;
    static std::map<std::string, std::string> cache;
    static UnDecFn fn = nullptr;
    static bool tried = false;
    std::lock_guard<std::mutex> lk(m);
    auto it = cache.find(mangled);
    if (it != cache.end()) return it->second;
    if (!tried) {
        tried = true;
        void* h = LoadLibraryA("dbghelp.dll");
        if (h) fn = (UnDecFn)GetProcAddress(h, "UnDecorateSymbolName");
    }
    std::string out = mangled;
    if (fn) {
        char buf[512];
        unsigned long n = fn(mangled.c_str(), buf, (unsigned long)sizeof buf, 0x1000u);
        if (n && buf[0]) { out.assign(buf); simplify_std_name(out); }
    }
    cache[mangled] = out;
    return out;
#else
    return mangled;
#endif
}

std::string sani(const std::string& raw) {
    /* Make an identifier safe for C: keep [A-Za-z0-9_], map the rest to '_'.
     * An MSVC-mangled `?...` name is demangled FIRST so the identifier reads as
     * `std__cout` / `std__basic_ostream_char___Osfx`, not mangled soup. */
    const std::string in = demangle_msvc(raw);
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')
            out.push_back(c);
        else
            out.push_back('_');
    }
    if (out.empty() || (out[0] >= '0' && out[0] <= '9'))
        out = "_" + out;
    return out;
}

/* ====================================================================== */
/*  Register model: canonical 64-bit register id + access width            */
/* ====================================================================== */

enum Reg {
    R_NONE = 0,
    R_RAX, R_RCX, R_RDX, R_RBX, R_RSP, R_RBP, R_RSI, R_RDI,
    R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_XMM0, R_XMM1, R_XMM2, R_XMM3, R_XMM4, R_XMM5, R_XMM6, R_XMM7,
    R_XMM8, R_XMM9, R_XMM10, R_XMM11, R_XMM12, R_XMM13, R_XMM14, R_XMM15,
    R_RIP,
    R_COUNT
};

/* Map an xmm/ymm/zmm capstone register to its shared R_XMM slot (ymm0's low 128
 * IS xmm0 — same physical register); R_NONE otherwise. Used by the wide-vector
 * memcpy modeling, which must recognize a ymm source that map_reg leaves R_NONE. */
Reg vec_reg(unsigned cr) {
    if (cr >= X86_REG_XMM0 && cr <= X86_REG_XMM15) return (Reg)(R_XMM0 + (int)(cr - X86_REG_XMM0));
    if (cr >= X86_REG_YMM0 && cr <= X86_REG_YMM15) return (Reg)(R_XMM0 + (int)(cr - X86_REG_YMM0));
    if (cr >= X86_REG_ZMM0 && cr <= X86_REG_ZMM15) return (Reg)(R_XMM0 + (int)(cr - X86_REG_ZMM0));
    return R_NONE;
}
void map_reg(unsigned cr, Reg& out, int& width) {
    out = R_NONE; width = 0;
    switch (cr) {
        case X86_REG_RAX: out = R_RAX; width = 8; break;
        case X86_REG_RCX: out = R_RCX; width = 8; break;
        case X86_REG_RDX: out = R_RDX; width = 8; break;
        case X86_REG_RBX: out = R_RBX; width = 8; break;
        case X86_REG_RSP: out = R_RSP; width = 8; break;
        case X86_REG_RBP: out = R_RBP; width = 8; break;
        case X86_REG_RSI: out = R_RSI; width = 8; break;
        case X86_REG_RDI: out = R_RDI; width = 8; break;
        case X86_REG_R8:  out = R_R8;  width = 8; break;
        case X86_REG_R9:  out = R_R9;  width = 8; break;
        case X86_REG_R10: out = R_R10; width = 8; break;
        case X86_REG_R11: out = R_R11; width = 8; break;
        case X86_REG_R12: out = R_R12; width = 8; break;
        case X86_REG_R13: out = R_R13; width = 8; break;
        case X86_REG_R14: out = R_R14; width = 8; break;
        case X86_REG_R15: out = R_R15; width = 8; break;
        case X86_REG_RIP: out = R_RIP; width = 8; break;
        case X86_REG_EAX: out = R_RAX; width = 4; break;
        case X86_REG_ECX: out = R_RCX; width = 4; break;
        case X86_REG_EDX: out = R_RDX; width = 4; break;
        case X86_REG_EBX: out = R_RBX; width = 4; break;
        case X86_REG_ESP: out = R_RSP; width = 4; break;
        case X86_REG_EBP: out = R_RBP; width = 4; break;
        case X86_REG_ESI: out = R_RSI; width = 4; break;
        case X86_REG_EDI: out = R_RDI; width = 4; break;
        case X86_REG_R8D: out = R_R8;  width = 4; break;
        case X86_REG_R9D: out = R_R9;  width = 4; break;
        case X86_REG_R10D: out = R_R10; width = 4; break;
        case X86_REG_R11D: out = R_R11; width = 4; break;
        case X86_REG_R12D: out = R_R12; width = 4; break;
        case X86_REG_R13D: out = R_R13; width = 4; break;
        case X86_REG_R14D: out = R_R14; width = 4; break;
        case X86_REG_R15D: out = R_R15; width = 4; break;
        case X86_REG_AX: out = R_RAX; width = 2; break;
        case X86_REG_CX: out = R_RCX; width = 2; break;
        case X86_REG_DX: out = R_RDX; width = 2; break;
        case X86_REG_BX: out = R_RBX; width = 2; break;
        case X86_REG_SP: out = R_RSP; width = 2; break;
        case X86_REG_BP: out = R_RBP; width = 2; break;
        case X86_REG_SI: out = R_RSI; width = 2; break;
        case X86_REG_DI: out = R_RDI; width = 2; break;
        case X86_REG_R8W: out = R_R8; width = 2; break;
        case X86_REG_R9W: out = R_R9; width = 2; break;
        case X86_REG_R10W: out = R_R10; width = 2; break;
        case X86_REG_R11W: out = R_R11; width = 2; break;
        case X86_REG_R12W: out = R_R12; width = 2; break;
        case X86_REG_R13W: out = R_R13; width = 2; break;
        case X86_REG_R14W: out = R_R14; width = 2; break;
        case X86_REG_R15W: out = R_R15; width = 2; break;
        case X86_REG_AL: out = R_RAX; width = 1; break;
        case X86_REG_CL: out = R_RCX; width = 1; break;
        case X86_REG_DL: out = R_RDX; width = 1; break;
        case X86_REG_BL: out = R_RBX; width = 1; break;
        case X86_REG_SIL: out = R_RSI; width = 1; break;
        case X86_REG_DIL: out = R_RDI; width = 1; break;
        case X86_REG_SPL: out = R_RSP; width = 1; break;
        case X86_REG_BPL: out = R_RBP; width = 1; break;
        case X86_REG_R8B: out = R_R8; width = 1; break;
        case X86_REG_R9B: out = R_R9; width = 1; break;
        case X86_REG_R10B: out = R_R10; width = 1; break;
        case X86_REG_R11B: out = R_R11; width = 1; break;
        case X86_REG_R12B: out = R_R12; width = 1; break;
        case X86_REG_R13B: out = R_R13; width = 1; break;
        case X86_REG_R14B: out = R_R14; width = 1; break;
        case X86_REG_R15B: out = R_R15; width = 1; break;
        case X86_REG_AH: out = R_RAX; width = 1; break;
        case X86_REG_CH: out = R_RCX; width = 1; break;
        case X86_REG_DH: out = R_RDX; width = 1; break;
        case X86_REG_BH: out = R_RBX; width = 1; break;
        /* SSE registers (width 16 = full xmm; scalar float ops use the low 4/8). */
        case X86_REG_XMM0: out = R_XMM0; width = 16; break;
        case X86_REG_XMM1: out = R_XMM1; width = 16; break;
        case X86_REG_XMM2: out = R_XMM2; width = 16; break;
        case X86_REG_XMM3: out = R_XMM3; width = 16; break;
        case X86_REG_XMM4: out = R_XMM4; width = 16; break;
        case X86_REG_XMM5: out = R_XMM5; width = 16; break;
        case X86_REG_XMM6: out = R_XMM6; width = 16; break;
        case X86_REG_XMM7: out = R_XMM7; width = 16; break;
        case X86_REG_XMM8: out = R_XMM8; width = 16; break;
        case X86_REG_XMM9: out = R_XMM9; width = 16; break;
        case X86_REG_XMM10: out = R_XMM10; width = 16; break;
        case X86_REG_XMM11: out = R_XMM11; width = 16; break;
        case X86_REG_XMM12: out = R_XMM12; width = 16; break;
        case X86_REG_XMM13: out = R_XMM13; width = 16; break;
        case X86_REG_XMM14: out = R_XMM14; width = 16; break;
        case X86_REG_XMM15: out = R_XMM15; width = 16; break;
        default: out = R_NONE; width = 0; break;
    }
}

/* ====================================================================== */
/*  Expression IR                                                          */
/* ====================================================================== */

enum class EK {
    Const, Reg, Var, Mem, Unary, Binary, Cast, Call, AddrOf, Ternary, Str
};

struct Expr;
using ExprP = std::shared_ptr<Expr>;

/* ====================================================================== */
/*  Expression node pool                                                   */
/* ====================================================================== */
/*
 * Every value in the IR is a heap-allocated Expr behind a shared_ptr, and every
 * pass clones subtrees, so a single function churns through a very large number
 * of small, identically-sized, short-lived allocations. Through the general
 * allocator that made the process heap lock — not the CPU — the ceiling on
 * parallel decompilation: throughput peaked around 8 workers and got WORSE at
 * 16, which is why the shell capped its thread count at 8.
 *
 * This is a thread-local, size-bucketed free-list pool. Allocation is a pop off
 * a list and deallocation is a push, with no atomics and no lock, so N workers
 * scale without contending. It sits behind std::allocate_shared, so ExprP stays
 * std::shared_ptr<Expr> and not one of the ~70 construction sites changes.
 *
 * SAFETY. The pool is per-thread, so a node freed on a different thread than it
 * was allocated on would migrate between free lists — harmless — but a node
 * still live when its owning thread exits would be a use-after-free if the
 * chunks were released. Two things make that impossible: no Expr ever escapes
 * the decompile that created it (the result is a std::string; neither FuncSig
 * nor PeTables, the only structures shared across threads, holds an ExprP), and
 * the chunks are DELIBERATELY LEAKED — never freed, even at thread exit — so any
 * pointer the pool has ever handed out stays valid for the life of the process.
 * The cost of that is bounded by peak concurrent usage, not by total work, since
 * freed blocks are always reused.
 *
 * DS_NO_EXPRPOOL falls back to the general allocator for A/B measurement.
 */
struct ExprPool {
    static constexpr size_t kGran    = 16;                  /* >= sizeof(void*) */
    static constexpr size_t kMaxSize = 512;                 /* larger -> global */
    static constexpr size_t kBuckets = kMaxSize / kGran + 1;
    static constexpr size_t kChunk   = 256 * 1024;

    void*  free_list[kBuckets] = {};
    char*  chunk = nullptr;
    size_t chunk_off = 0, chunk_left = 0;

    void* alloc(size_t n) {
        if (n == 0) n = 1;
        if (n > kMaxSize) return ::operator new(n);
        size_t b  = (n + kGran - 1) / kGran;
        size_t sz = b * kGran;
        if (void* p = free_list[b]) {
            free_list[b] = *reinterpret_cast<void**>(p);
            return p;
        }
        if (chunk_left < sz) {
            /* Intentionally leaked: see SAFETY above. */
            chunk = static_cast<char*>(::operator new(kChunk));
            chunk_off = 0;
            chunk_left = kChunk;
        }
        void* p = chunk + chunk_off;
        chunk_off  += sz;
        chunk_left -= sz;
        return p;
    }
    void release(void* p, size_t n) {
        if (n == 0) n = 1;
        if (n > kMaxSize) { ::operator delete(p); return; }
        size_t b = (n + kGran - 1) / kGran;
        *reinterpret_cast<void**>(p) = free_list[b];
        free_list[b] = p;
    }
};

inline ExprPool& expr_pool() {
    static thread_local ExprPool p;
    return p;
}
inline bool expr_pool_off() {
    static const bool v = std::getenv("DS_NO_EXPRPOOL") != nullptr;
    return v;
}

/* Minimal STL allocator over the pool. allocate_shared rebinds this to its own
 * combined control-block+object type, so the pool must serve arbitrary small
 * sizes rather than just sizeof(Expr) — hence the size buckets. */
template <class T>
struct PoolAlloc {
    using value_type = T;
    PoolAlloc() noexcept {}
    template <class U> PoolAlloc(const PoolAlloc<U>&) noexcept {}
    T* allocate(size_t n) {
        size_t bytes = n * sizeof(T);
        return static_cast<T*>(expr_pool_off() ? ::operator new(bytes)
                                               : expr_pool().alloc(bytes));
    }
    void deallocate(T* p, size_t n) noexcept {
        if (expr_pool_off()) { ::operator delete(p); return; }
        expr_pool().release(p, n * sizeof(T));
    }
    template <class U> bool operator==(const PoolAlloc<U>&) const noexcept { return true; }
    template <class U> bool operator!=(const PoolAlloc<U>&) const noexcept { return false; }
};

/* The single construction point for IR nodes. */
template <class... A>
inline ExprP new_expr(A&&... args) {
    return std::allocate_shared<Expr>(PoolAlloc<Expr>(), std::forward<A>(args)...);
}

struct Expr {
    EK kind;

    int64_t cval = 0;          /* Const */

    Reg     reg = R_NONE;      /* Reg : transient symbolic register read */
    int     width = 4;         /* operation/value byte width: 1,2,4,8 */
    bool    is_unsigned = false;
    bool    is_float = false;  /* FP-typed: Const holds the IEEE-754 bit pattern in
                                * cval (width 4 -> float, 8 -> double); Binary marks
                                * a scalar SSE op so constants under it print as
                                * float literals and int folding is suppressed. */

    std::string name;          /* Var : recovered local/param name */

    ExprP a, b, c;             /* operands; c used by Ternary */

    std::string op;            /* Unary/Binary/Cast/Ternary op or cast text */

    std::string callee;        /* Call */
    std::vector<ExprP> args;
    bool indirect = false;
    int  ret_kind = 0;         /* call return kind (0 void,1 int,2 ll) */

    std::string text;          /* Str : already-formatted literal text */
    bool hex_hint = false;      /* Const: render as hex (a bitmask/magic in a bitwise op) */
    bool char_hint = false;     /* Const: render as a char literal ('A') — a byte comparison */
    bool dec_hint = false;      /* Const: render as DECIMAL (a recovered divisor: `x / 10`) */
    bool null_hint = false;     /* Const 0: render as NULL (compared/assigned to a pointer) */
    bool addr_hint = false;     /* Const: value is a static-data ADDRESS in a proven pointer
                                 * position -> render `&<named_global>` (address-of a global) */
};

ExprP mkConst(int64_t v, int w = 4, bool u = false) {
    auto e = new_expr(); e->kind = EK::Const; e->cval = v;
    e->width = w; e->is_unsigned = u; return e;
}
ExprP mkReg(Reg r, int w) {
    auto e = new_expr(); e->kind = EK::Reg;
    e->reg = r; e->width = w; return e;
}
ExprP mkVar(const std::string& n, int w = 4, bool u = false) {
    auto e = new_expr(); e->kind = EK::Var; e->name = n;
    e->width = w; e->is_unsigned = u; return e;
}
ExprP mkMem(ExprP addr, int w, bool u = false) {
    auto e = new_expr(); e->kind = EK::Mem; e->a = addr;
    e->width = w; e->is_unsigned = u; return e;
}
ExprP mkUnary(const std::string& op, ExprP x, int w) {
    auto e = new_expr(); e->kind = EK::Unary; e->op = op;
    e->a = x; e->width = w; return e;
}
ExprP mkBinary(const std::string& op, ExprP l, ExprP r, int w, bool u = false) {
    auto e = new_expr(); e->kind = EK::Binary; e->op = op;
    e->a = l; e->b = r; e->width = w; e->is_unsigned = u; return e;
}
ExprP mkCast(const std::string& cast, ExprP x, int w, bool u = false) {
    /* Collapse an immediately-redundant identical nested cast: (T)(T)y == (T)y.
     * Only fires when the inner node is a Cast with the SAME cast text, width
     * and signedness, so a genuine narrowing/widening or sign-change cast is
     * never dropped. Behavior-preserving and reduces (int)(int)x noise toward
     * Hex-Rays quality. Generalizes to any binary. */
    if (x && x->kind == EK::Cast && x->op == cast &&
        x->width == w && x->is_unsigned == u) {
        return x;
    }
    auto e = new_expr(); e->kind = EK::Cast; e->op = cast;
    e->a = x; e->width = w; e->is_unsigned = u; return e;
}
ExprP mkAddrOf(ExprP x) {
    auto e = new_expr(); e->kind = EK::AddrOf; e->a = x;
    e->width = 8; return e;
}
ExprP mkTernary(ExprP cond, ExprP t, ExprP f, int w) {
    auto e = new_expr(); e->kind = EK::Ternary;
    e->a = cond; e->b = t; e->c = f; e->width = w; return e;
}
ExprP mkText(const std::string& t, int w = 8) {
    auto e = new_expr(); e->kind = EK::Str; e->text = t;
    e->width = w; return e;
}

/* ===================================================================== */
/*  Whole-program PE tables (parsed ONCE per engine, shared read-only).    */
/*  reloc64 : RVAs of IMAGE_REL_BASED_DIR64 base-relocation slots — every   */
/*    such 8-byte image word holds an absolute pointer (fixed up at load),  */
/*    so a read-only global at one of these RVAs is a POINTER, not an int.  */
/*  pdata   : x64 exception directory RUNTIME_FUNCTION[] — authoritative    */
/*    [begin,end) per function + the UNWIND_INFO rva; sorted by begin.      */
/*  Sections are found by name (.reloc/.pdata); the data directory (headers */
/*  mapped at rva 0 by binary-parser build_image) is the stripped-name      */
/*  fallback. Thread-safe: dumptool shares one immutable engine across N    */
/*  worker threads, so we compute under a lock and hand back an immutable   */
/*  shared_ptr that concurrent readers can use lock-free.                   */
/* ===================================================================== */
/* Recovered exception-handling structure for one function (from .pdata/.xdata). */
struct SehScope { uint32_t begin = 0, end = 0, filter = 0, target = 0; }; /* filter==0 => __finally */
struct CppCatch { std::string type; uint32_t handler = 0; bool by_ref = false; };
struct CppTry { int low = 0, high = 0; std::vector<CppCatch> catches; };
struct EHInfo {
    std::vector<SehScope> seh;   /* __C_specific_handler scope table -> __try/__except/__finally */
    std::vector<CppTry>   cpp;   /* __CxxFrameHandler3 (v3) FuncInfo -> try/catch */
    bool any() const { return !seh.empty() || !cpp.empty(); }
};

struct PeTables {
    std::unordered_set<uint64_t> reloc64;
    struct RF { uint32_t begin = 0, end = 0, unwind = 0; };
    std::vector<RF> pdata;                     /* sorted by begin */
    std::map<uint64_t, EHInfo> eh;             /* fn begin rva -> recovered EH */
    bool has_reloc = false, has_pdata = false;
};

static bool pe_rd_u8(const ds_engine* e, uint64_t rva, uint8_t& o) {
    if (!e || !e->image || rva + 1 > e->image_size) return false;
    o = e->image[rva]; return true;
}
static bool pe_rd_u16(const ds_engine* e, uint64_t rva, uint16_t& o) {
    if (!e || !e->image || rva + 2 > e->image_size) return false;
    o = (uint16_t)(e->image[rva] | (e->image[rva + 1] << 8)); return true;
}
/* Turn an MSVC RTTI TypeDescriptor mangled name into a readable C++ type:
 * ".?AVexception@std@@" -> "std::exception", ".?AUFoo@@" -> "Foo". Best-effort. */
static std::string pe_demangle_type(const std::string& raw) {
    std::string s = raw;
    if (s.rfind(".?A", 0) == 0) s = s.substr(4);       /* drop .?AV / .?AU / .?AW tag */
    if (s.size() >= 2 && s.compare(s.size() - 2, 2, "@@") == 0) s = s.substr(0, s.size() - 2);
    /* segments are innermost-first, separated by '@' -> reverse into A::B::C */
    std::vector<std::string> parts; std::string cur;
    for (char c : s) { if (c == '@') { if (!cur.empty()) parts.push_back(cur); cur.clear(); } else cur += c; }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.empty()) return raw;
    std::string out;
    for (size_t i = parts.size(); i-- > 0; ) { out += parts[i]; if (i) out += "::"; }
    return out;
}
static bool pe_rd_u32(const ds_engine* e, uint64_t rva, uint32_t& o) {
    if (!e || !e->image || rva + 4 > e->image_size) return false;
    o = 0; for (int i = 0; i < 4; i++) o |= (uint32_t)e->image[rva + i] << (8 * i);
    return true;
}
/* MSVC __CxxFrameHandler4 variable-length uint: the low bits of the first byte encode the
 * byte-length (1..4), the value is the rest shifted down. Advances `rva`. */
static bool pe_rd_fh4uint(const ds_engine* e, uint64_t& rva, uint32_t& out) {
    uint8_t b; if (!pe_rd_u8(e, rva, b)) return false;
    if ((b & 1) == 0)      { out = b >> 1; rva += 1; }
    else if ((b & 2) == 0) { uint16_t w; if (!pe_rd_u16(e, rva, w)) return false; out = w >> 2; rva += 2; }
    else if ((b & 4) == 0) { uint32_t w = 0; for (int i = 0; i < 3; i++) { uint8_t x; if (!pe_rd_u8(e, rva + i, x)) return false; w |= (uint32_t)x << (8 * i); } out = w >> 3; rva += 3; }
    else if ((b & 8) == 0) { uint32_t w; if (!pe_rd_u32(e, rva, w)) return false; out = w >> 4; rva += 4; }
    else return false;
    return true;
}
static const ds_segment* pe_seg_named(const ds_engine* e, const char* nm) {
    if (!e) return nullptr;
    for (size_t i = 0; i < e->segment_len; i++)
        if (std::strncmp(e->segments[i].name, nm, sizeof e->segments[i].name) == 0)
            return &e->segments[i];
    return nullptr;
}
/* Data directory [idx] (rva,size) from the PE headers mapped at rva 0. */
static bool pe_data_dir(const ds_engine* e, int idx, uint32_t& rva, uint32_t& sz) {
    uint16_t mz; if (!pe_rd_u16(e, 0, mz) || mz != 0x5A4D) return false;      /* 'MZ' */
    uint32_t lfanew; if (!pe_rd_u32(e, 0x3C, lfanew)) return false;
    uint32_t sig; if (!pe_rd_u32(e, lfanew, sig) || sig != 0x00004550) return false; /* PE\0\0 */
    uint64_t opt = (uint64_t)lfanew + 4 + 20;                                 /* skip COFF header */
    uint16_t magic; if (!pe_rd_u16(e, opt, magic)) return false;
    uint64_t dirs;
    if (magic == 0x20B) dirs = opt + 112;        /* PE32+ */
    else if (magic == 0x10B) dirs = opt + 96;    /* PE32  */
    else return false;
    uint64_t off = dirs + (uint64_t)idx * 8;
    return pe_rd_u32(e, off, rva) && pe_rd_u32(e, off + 4, sz);
}

static std::shared_ptr<const PeTables> compute_pe_tables(const ds_engine* e) {
    auto t = std::make_shared<PeTables>();
    if (!e || !e->image) return t;
    /* ---- base relocations (.reloc / data dir 5) ---- */
    uint64_t rr = 0, rsz = 0;
    if (const ds_segment* s = pe_seg_named(e, ".reloc")) { rr = s->rva; rsz = s->size; }
    else { uint32_t a, z; if (pe_data_dir(e, 5, a, z) && a) { rr = a; rsz = z; } }
    if (rr && rsz) {
        uint64_t p = rr, end = rr + rsz;
        while (p + 8 <= end) {
            uint32_t page, bsz;
            if (!pe_rd_u32(e, p, page) || !pe_rd_u32(e, p + 4, bsz)) break;
            if (bsz < 8 || p + bsz > end) break;
            uint64_t n = (bsz - 8) / 2, q = p + 8;
            for (uint64_t i = 0; i < n; i++) {
                uint16_t ent; if (!pe_rd_u16(e, q + i * 2, ent)) break;
                if ((ent >> 12) == 10)                       /* IMAGE_REL_BASED_DIR64 */
                    t->reloc64.insert((uint64_t)page + (ent & 0x0FFF));
            }
            p += bsz;
        }
        t->has_reloc = !t->reloc64.empty();
    }
    /* ---- exception directory RUNTIME_FUNCTION[] (.pdata / data dir 3) ---- */
    uint64_t pr = 0, psz = 0;
    if (const ds_segment* s = pe_seg_named(e, ".pdata")) { pr = s->rva; psz = s->size; }
    else { uint32_t a, z; if (pe_data_dir(e, 3, a, z) && a) { pr = a; psz = z; } }
    if (pr && psz) {
        uint64_t n = psz / 12;
        for (uint64_t i = 0; i < n; i++) {
            uint64_t base = pr + i * 12; uint32_t b, en, u;
            if (!pe_rd_u32(e, base, b) || !pe_rd_u32(e, base + 4, en) || !pe_rd_u32(e, base + 8, u)) break;
            if (b == 0 && en == 0 && u == 0) break;          /* zero terminator */
            if (en <= b) continue;
            PeTables::RF rf; rf.begin = b; rf.end = en; rf.unwind = u;
            t->pdata.push_back(rf);
        }
        std::sort(t->pdata.begin(), t->pdata.end(),
                  [](const PeTables::RF& x, const PeTables::RF& y) { return x.begin < y.begin; });
        t->has_pdata = !t->pdata.empty();
    }
    /* ---- exception handling (.xdata UNWIND_INFO -> SEH scope tables / C++ FuncInfo) ---- */
    for (const auto& rf : t->pdata) {
        uint8_t vf, cnt;
        if (!pe_rd_u8(e, rf.unwind, vf) || !pe_rd_u8(e, rf.unwind + 2, cnt)) continue;
        uint8_t flags = vf >> 3;
        if (flags & 0x4) continue;                 /* chained fragment */
        if (!(flags & 0x3)) continue;              /* no exception/unwind handler */
        uint64_t hs = rf.unwind + 4 + (uint64_t)((cnt + 1) & ~1) * 2;   /* aligned unwind-code array */
        uint64_t data = hs + 4;                    /* skip the 4-byte handler RVA */
        EHInfo info;
        /* (A) __C_specific_handler SCOPE_TABLE: u32 Count, then Count*{Begin,End,Handler,Target}.
         * Validated: sane count and every [Begin,End) inside the function -> real SEH. */
        uint32_t scount;
        if (pe_rd_u32(e, data, scount) && scount >= 1 && scount <= 64) {
            bool ok = true;
            std::vector<SehScope> scopes;
            for (uint32_t k = 0; k < scount && ok; ++k) {
                uint64_t rec = data + 4 + (uint64_t)k * 16;
                SehScope s;
                if (!pe_rd_u32(e, rec, s.begin) || !pe_rd_u32(e, rec + 4, s.end) ||
                    !pe_rd_u32(e, rec + 8, s.filter) || !pe_rd_u32(e, rec + 12, s.target)) { ok = false; break; }
                if (!(s.begin >= rf.begin && s.end <= rf.end && s.begin < s.end)) { ok = false; break; }
                scopes.push_back(s);
            }
            if (ok && !scopes.empty()) info.seh = std::move(scopes);
        }
        /* (B) __CxxFrameHandler3 (v3) FuncInfo: magic 0x1993052x -> try/catch. v4 is a
         * different compressed encoding and is intentionally left for a later pass. */
        if (info.seh.empty()) {
            uint32_t fi;
            if (pe_rd_u32(e, data, fi) && fi) {
                uint32_t magic;
                if (pe_rd_u32(e, fi, magic) &&
                    (magic == 0x19930520u || magic == 0x19930521u || magic == 0x19930522u)) {
                    uint32_t nTry = 0, pTry = 0;
                    pe_rd_u32(e, fi + 12, nTry); pe_rd_u32(e, fi + 16, pTry);
                    for (uint32_t ti = 0; ti < nTry && ti < 64 && pTry; ++ti) {
                        uint64_t to = (uint64_t)pTry + (uint64_t)ti * 20;
                        uint32_t tl, th, ch, nc, pha;
                        if (!pe_rd_u32(e, to, tl) || !pe_rd_u32(e, to + 4, th) ||
                            !pe_rd_u32(e, to + 8, ch) || !pe_rd_u32(e, to + 12, nc) ||
                            !pe_rd_u32(e, to + 16, pha)) break;
                        CppTry ct; ct.low = (int)tl; ct.high = (int)th;
                        for (uint32_t ci = 0; ci < nc && ci < 32 && pha; ++ci) {
                            uint64_t ho = (uint64_t)pha + (uint64_t)ci * 20;   /* x64 HandlerType = 20 bytes */
                            uint32_t adj, pType, hadr;
                            if (!pe_rd_u32(e, ho, adj) || !pe_rd_u32(e, ho + 4, pType) ||
                                !pe_rd_u32(e, ho + 12, hadr)) break;
                            CppCatch cc; cc.handler = hadr;
                            if (pType) {                                       /* TypeDescriptor.name @ +16 */
                                std::string nm;
                                for (int j = 0; j < 512; ++j) {
                                    uint8_t b; if (!pe_rd_u8(e, (uint64_t)pType + 16 + j, b) || !b) break;
                                    nm += (char)b;
                                }
                                cc.type = pe_demangle_type(nm);
                            }
                            ct.catches.push_back(std::move(cc));
                        }
                        info.cpp.push_back(std::move(ct));
                    }
                }
            }
        }
        /* (C) __CxxFrameHandler4 (FH4, modern MSVC /O2 default): the FuncInfo has NO magic and
         * a compressed variable-length-int layout the v3 test above skips. Decode it to the SAME
         * CppTry/CppCatch table the renderer consumes. Runs only when v3/SEH found nothing. The
         * decisive validator is that a non-null caught-type dispType must point at a `.?A`
         * TypeDescriptor -- random data essentially never satisfies it. All-or-nothing. DS_NO_EH4. */
        if (info.seh.empty() && info.cpp.empty() && !std::getenv("DS_NO_EH4")) {
            uint32_t fi;
            if (pe_rd_u32(e, data, fi) && fi && ds_rva_is_mapped(e, fi) && !ds_rva_is_exec(e, fi)) {
                uint8_t hdr;
                if (pe_rd_u8(e, fi, hdr) && !(hdr & 0x80)) {
                    uint64_t p = fi + 1; uint32_t t32; bool ok = true;
                    if (hdr & 0x04) { if (!pe_rd_fh4uint(e, p, t32)) ok = false; }   /* bbtFlags */
                    if (ok && (hdr & 0x08)) p += 4;                                  /* dispUnwindMap */
                    uint32_t dispTry = 0, dispIP = 0;
                    if (ok && (hdr & 0x10)) { if (!pe_rd_u32(e, p, dispTry)) ok = false; p += 4; }
                    if (ok) { if (!pe_rd_u32(e, p, dispIP)) ok = false; p += 4; }
                    if (ok && dispTry && ds_rva_is_mapped(e, dispTry)) {
                        uint64_t tp = dispTry; uint32_t nTry = 0;
                        if (pe_rd_fh4uint(e, tp, nTry) && nTry >= 1 && nTry <= 64) {
                            for (uint32_t ti = 0; ti < nTry && ok; ++ti) {
                                uint32_t tl, th, chh, dha;
                                if (!pe_rd_fh4uint(e, tp, tl) || !pe_rd_fh4uint(e, tp, th) ||
                                    !pe_rd_fh4uint(e, tp, chh) || !pe_rd_u32(e, tp, dha)) { ok = false; break; }
                                tp += 4;
                                if (!ds_rva_is_mapped(e, dha)) { ok = false; break; }
                                CppTry ct; ct.low = (int)tl; ct.high = (int)th;
                                uint64_t hp = dha; uint32_t nC = 0;
                                if (!pe_rd_fh4uint(e, hp, nC) || nC > 32) { ok = false; break; }
                                for (uint32_t ci = 0; ci < nC && ok; ++ci) {
                                    uint8_t H; if (!pe_rd_u8(e, hp, H)) { ok = false; break; } hp += 1;
                                    uint32_t adj = 0, dispType = 0, dc = 0, dh = 0, tmp;
                                    if ((H & 0x01) && !pe_rd_fh4uint(e, hp, adj)) { ok = false; break; }
                                    if (H & 0x02) { if (!pe_rd_u32(e, hp, dispType)) { ok = false; break; } hp += 4; }
                                    if ((H & 0x04) && !pe_rd_fh4uint(e, hp, dc)) { ok = false; break; }
                                    if (!pe_rd_u32(e, hp, dh)) { ok = false; break; } hp += 4;   /* dispOfHandler */
                                    if ((H & 0x08) && !pe_rd_fh4uint(e, hp, tmp)) { ok = false; break; }
                                    if ((H & 0x10) && !pe_rd_fh4uint(e, hp, tmp)) { ok = false; break; }
                                    if ((H & 0x20) && !pe_rd_fh4uint(e, hp, tmp)) { ok = false; break; }
                                    CppCatch cc; cc.handler = dh;
                                    if (dispType) {
                                        if (!ds_rva_is_mapped(e, dispType)) { ok = false; break; }
                                        std::string nm;
                                        for (int j = 0; j < 512; ++j) {
                                            uint8_t x; if (!pe_rd_u8(e, (uint64_t)dispType + 16 + j, x) || !x) break;
                                            nm += (char)x;
                                        }
                                        if (nm.rfind(".?A", 0) != 0) { ok = false; break; }   /* strong validator */
                                        cc.type = pe_demangle_type(nm); cc.by_ref = (adj & 0x08) != 0;
                                    }
                                    ct.catches.push_back(std::move(cc));
                                }
                                if (ok) info.cpp.push_back(std::move(ct));
                            }
                            if (!ok) info.cpp.clear();   /* never emit a partial/garbage table */
                        }
                    }
                }
            }
        }
        if (info.any()) t->eh[rf.begin] = std::move(info);
    }
    return t;
}

static std::shared_ptr<const PeTables> get_pe_tables(const ds_engine* e) {
    static std::mutex m;
    static std::map<const ds_engine*, std::shared_ptr<const PeTables>> cache;
    std::lock_guard<std::mutex> lk(m);
    auto it = cache.find(e);
    if (it != cache.end()) return it->second;
    auto t = compute_pe_tables(e);
    cache[e] = t;
    return t;
}

bool isConst(const ExprP& e) { return e && e->kind == EK::Const; }

ExprP clone(const ExprP& e) {
    if (!e) return nullptr;
    auto c = new_expr(*e);
    c->a = clone(e->a);
    c->b = clone(e->b);
    c->c = clone(e->c);
    c->args.clear();
    for (auto& ar : e->args) c->args.push_back(clone(ar));
    return c;
}

bool reads_reg(const ExprP& e, Reg r) {
    if (!e) return false;
    if (e->kind == EK::Reg && e->reg == r) return true;
    if (reads_reg(e->a, r) || reads_reg(e->b, r) || reads_reg(e->c, r)) return true;
    for (auto& ar : e->args) if (reads_reg(ar, r)) return true;
    return false;
}
bool reads_any_reg(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Reg) return true;
    if (reads_any_reg(e->a) || reads_any_reg(e->b) || reads_any_reg(e->c)) return true;
    for (auto& ar : e->args) if (reads_any_reg(ar)) return true;
    return false;
}
bool reads_mem(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Mem) return true;
    if (reads_mem(e->a) || reads_mem(e->b) || reads_mem(e->c)) return true;
    for (auto& ar : e->args) if (reads_mem(ar)) return true;
    return false;
}
bool has_call(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Call) return true;
    if (has_call(e->a) || has_call(e->b) || has_call(e->c)) return true;
    for (auto& ar : e->args) if (has_call(ar)) return true;
    return false;
}
/* Is this callee a PURE value computation — safe to hoist, duplicate, or drop?
 *
 * The `__` prefix is the general rule (__bsr / __umulh / __pmovmskb / __mulh ...):
 * value-producing, side-effect-free reads. Two exceptions matter:
 *  - __stos* / __movs* WRITE MEMORY despite the `__` prefix. Treating them as pure
 *    would let a CSE pass collapse or a DCE pass delete a real memory fill/copy.
 *  - the _rotl/_rotr family IS pure, but MSVC spells it with a SINGLE underscore, so
 *    the `__` test misses it — which left dead `v = _rotl(...)` temps uncollectable. */
bool is_pure_callee(const std::string& c) {
    /* NOT pure despite the `__` prefix: */
    if (c.rfind("__stos", 0) == 0 || c.rfind("__movs", 0) == 0) return false; /* write memory */
    /* __scas* only READS memory, but it is not CSE-safe: a store between two identical
     * scans changes what the second one finds, so collapsing them would be wrong. */
    if (c.rfind("__scas", 0) == 0) return false;
    /* __cmps* (rep cmps = memcmp): READS memory only, but same CSE hazard as __scas —
     * an intervening store to either buffer changes the second compare's result. */
    if (c.rfind("__cmps", 0) == 0) return false;
    if (c == "__writemxcsr") return false;              /* writes the SSE control word */
    if (c == "__fastfail") return false;                /* noreturn: aborts the process */
    /* NOT idempotent: each read returns a different value, so CSE must never collapse
     * two of them into one (they are pure in the no-side-effect sense, but not equal). */
    if (c == "__rdtsc" || c == "_xgetbv") return false;
    if (c == "__syscall") return false;   /* a kernel call: arbitrary side effects */
    if (c == "__security_check_cookie" || c == "__chkstk") return false;      /* may not return */
    /* The opaque stand-in for an unmodeled op that WROTE MEMORY. The call IS the side
     * effect, so treating it as pure would let CSE collapse two of them or DSE delete it
     * outright — silently restoring the very dropped store it was added to disclose (and
     * un-counting it from the confidence header, which only counts intrinsics that survive
     * into the body). The wide-vector moves are the ones that reach this path: the VEX
     * width guard refuses to remap any ymm/zmm form. */
    if (c.rfind("__vmov", 0) == 0 || c.rfind("__vpmaskmov", 0) == 0) return false;
    if (c.rfind("__", 0) == 0) return true;
    return c.rfind("_rotl", 0) == 0 || c.rfind("_rotr", 0) == 0;
}
/* Like has_call but IGNORES pure compiler intrinsics: a subexpression containing one
 * is safe to hoist/CSE. Only a real callee (fun_x / import / rand) — or a memory-
 * writing intrinsic — blocks CSE. Used by the CSE passes so an intrinsic-bearing
 * address reused across an unrolled access collapses to one temp instead of a
 * multi-KB re-inlined line. */
bool has_impure_call(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Call && !is_pure_callee(e->callee)) return true;
    if (has_impure_call(e->a) || has_impure_call(e->b) || has_impure_call(e->c)) return true;
    for (auto& ar : e->args) if (has_impure_call(ar)) return true;
    return false;
}
int count_impure_calls(const ExprP& e) {
    if (!e) return 0;
    int n = (e->kind == EK::Call && !is_pure_callee(e->callee)) ? 1 : 0;
    n += count_impure_calls(e->a) + count_impure_calls(e->b) + count_impure_calls(e->c);
    for (auto& ar : e->args) n += count_impure_calls(ar);
    return n;
}
/* Does `nm` occur at a position NOT nested inside a Call's arguments? A value
 * nested in another call's args (`g(nm)`) evaluates BEFORE that call, so an
 * impure-call value inlined there keeps its order; a sibling (`nm + g()`) does
 * not. A Call's callee/indirect-target (e->a) IS a sibling, so it is checked. */
bool reads_var_outside_call_args(const ExprP& e, const std::string& nm) {
    if (!e) return false;
    if (e->kind == EK::Var) return e->name == nm;
    if (e->kind == EK::Call) return reads_var_outside_call_args(e->a, nm);  /* args nested */
    if (reads_var_outside_call_args(e->a, nm)) return true;
    if (reads_var_outside_call_args(e->b, nm)) return true;
    if (reads_var_outside_call_args(e->c, nm)) return true;
    for (auto& ar : e->args) if (reads_var_outside_call_args(ar, nm)) return true;
    return false;
}
bool reads_named_var(const ExprP& e, const std::string& nm) {
    if (!e) return false;
    if (e->kind == EK::Var && e->name == nm) return true;
    if (reads_named_var(e->a, nm) || reads_named_var(e->b, nm) ||
        reads_named_var(e->c, nm)) return true;
    for (auto& ar : e->args) if (reads_named_var(ar, nm)) return true;
    return false;
}
/* Replace every Var node named `nm` with a clone of `repl` (used to break a phi
 * copy cycle by redirecting reads to a saved temp). */
ExprP subst_named_var(const ExprP& e, const std::string& nm, const ExprP& repl) {
    if (!e) return e;
    if (e->kind == EK::Var && e->name == nm) return clone(repl);
    auto c = new_expr(*e);
    c->a = subst_named_var(e->a, nm, repl);
    c->b = subst_named_var(e->b, nm, repl);
    c->c = subst_named_var(e->c, nm, repl);
    c->args.clear();
    for (auto& ar : e->args) c->args.push_back(subst_named_var(ar, nm, repl));
    return c;
}
/* Replace every subtree exprEqual to `target` with a clone of `repl`. Used to
 * rebind a loop-exit/return/switch expression built from the PRE-increment value
 * of an induction var (`i+1`) to the phi variable after `i = i+1` is emitted. */
bool exprEqual(const ExprP& a, const ExprP& b);   /* defined just below */
ExprP subst_subtree(const ExprP& e, const ExprP& target, const ExprP& repl) {
    if (!e) return e;
    if (exprEqual(e, target)) return clone(repl);
    auto c = new_expr(*e);
    c->a = subst_subtree(e->a, target, repl);
    c->b = subst_subtree(e->b, target, repl);
    c->c = subst_subtree(e->c, target, repl);
    c->args.clear();
    for (auto& ar : e->args) c->args.push_back(subst_subtree(ar, target, repl));
    return c;
}
/* True when `e` provably evaluates to 0 or 1 (a setcc/comparison/logical result,
 * or a widening cast thereof). Used to drop the `& 0xff` the movzx of a setcc
 * byte lifts to, and similar no-op masks. */
bool is_bool_value(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Binary) {
        const std::string& o = e->op;
        return o=="=="||o=="!="||o=="<"||o=="<="||o==">"||o==">="||o=="&&"||o=="||";
    }
    if (e->kind == EK::Unary && e->op == "!") return true;
    if (e->kind == EK::Cast) return is_bool_value(e->a);
    if (e->kind == EK::Const) return e->cval == 0 || e->cval == 1;
    return false;
}
/* Total node count of an expression tree (for CSE size thresholds). */
int node_count(const ExprP& e) {
    if (!e) return 0;
    int n = 1 + node_count(e->a) + node_count(e->b) + node_count(e->c);
    for (auto& ar : e->args) n += node_count(ar);
    return n;
}
/* Count DISTINCT nodes in the expression DAG — a shared_ptr subtree reused N
 * times counts ONCE. node_count flattens the DAG, so a value shared across an
 * unrolled access explodes its count and cse_expr then bails on exactly the trees
 * that most need collapsing (an 81x-shared cmov index rendered as a 5 KB line).
 * The distinct-node count stays small for such DAGs, letting CSE proceed. */
void dag_nodes(const ExprP& e, std::set<const Expr*>& seen) {
    if (!e || seen.count(e.get())) return;
    seen.insert(e.get());
    dag_nodes(e->a, seen); dag_nodes(e->b, seen); dag_nodes(e->c, seen);
    for (auto& ar : e->args) dag_nodes(ar, seen);
}
int dag_node_count(const ExprP& e) { std::set<const Expr*> s; dag_nodes(e, s); return (int)s.size(); }
/* Collect every internal (non-leaf) subexpression — CSE candidates. */
void collect_subs(const ExprP& e, std::vector<ExprP>& out) {
    if (!e) return;
    if (e->kind==EK::Binary || e->kind==EK::Unary || e->kind==EK::Cast ||
        e->kind==EK::Mem || e->kind==EK::Ternary)
        out.push_back(e);
    collect_subs(e->a, out); collect_subs(e->b, out); collect_subs(e->c, out);
    for (auto& ar : e->args) collect_subs(ar, out);
}
/* Collect the names of all Var leaves referenced by `e`. */
void collect_var_names(const ExprP& e, std::set<std::string>& out) {
    if (!e) return;
    if (e->kind == EK::Var) out.insert(e->name);
    collect_var_names(e->a, out); collect_var_names(e->b, out); collect_var_names(e->c, out);
    for (auto& ar : e->args) collect_var_names(ar, out);
}
/* Count non-overlapping occurrences of `target` within `e`. */
int count_occ(const ExprP& e, const ExprP& target) {
    if (!e) return 0;
    if (exprEqual(e, target)) return 1;
    int n = count_occ(e->a,target)+count_occ(e->b,target)+count_occ(e->c,target);
    for (auto& ar : e->args) n += count_occ(ar, target);
    return n;
}
/* True when `e` references an `in_<REG>` backstop placeholder (an unrecovered
 * value). Used to refuse a switch-selector rebind that would leak one. */
bool expr_has_in_backstop(const ExprP& e) {
    if (!e) return false;
    if (e->kind == EK::Var && e->name.size() > 3 && e->name.compare(0,3,"in_") == 0)
        return true;
    if (expr_has_in_backstop(e->a) || expr_has_in_backstop(e->b) ||
        expr_has_in_backstop(e->c)) return true;
    for (auto& ar : e->args) if (expr_has_in_backstop(ar)) return true;
    return false;
}
/* True when `e` contains a memory load whose address exprEquals `addr` — i.e. a
 * cached register value that a store to `addr` would silently clobber. */
bool expr_loads_addr(const ExprP& e, const ExprP& addr) {
    if (!e) return false;
    if (e->kind == EK::Mem && e->a && exprEqual(e->a, addr)) return true;
    if (expr_loads_addr(e->a, addr) || expr_loads_addr(e->b, addr) ||
        expr_loads_addr(e->c, addr)) return true;
    for (auto& ar : e->args) if (expr_loads_addr(ar, addr)) return true;
    return false;
}

bool exprEqual(const ExprP& a, const ExprP& b) {
    if (!a || !b) return a == b;
    if (a->kind != b->kind) return false;
    switch (a->kind) {
        case EK::Const: return a->cval == b->cval;
        case EK::Reg:   return a->reg == b->reg;
        case EK::Var:   return a->name == b->name;
        case EK::Mem:   return exprEqual(a->a, b->a) && a->width == b->width;
        case EK::Unary: return a->op == b->op && exprEqual(a->a, b->a);
        case EK::Binary:return a->op == b->op && exprEqual(a->a, b->a) &&
                               exprEqual(a->b, b->b);
        case EK::Cast:  return a->op == b->op && exprEqual(a->a, b->a);
        case EK::AddrOf:return exprEqual(a->a, b->a);
        case EK::Str:   return a->text == b->text;
        case EK::Ternary: return exprEqual(a->a, b->a) && exprEqual(a->b, b->b) &&
                                 exprEqual(a->c, b->c);
        case EK::Call: {
            /* Only PURE compiler intrinsics (__bsr/__umulh/__pmovmskb/...) compare
             * equal — they are side-effect-free reads, so treating two identical
             * ones as the SAME value is sound (lets CSE collapse an intrinsic-bearing
             * address recomputed N times). A real callee (rand/fun_x) stays UNequal
             * so `rand() - rand()` is never folded to 0 nor CSE-merged. */
            if (a->callee != b->callee || a->indirect != b->indirect) return false;
            if (a->callee.rfind("__", 0) != 0) return false;
            if (a->args.size() != b->args.size()) return false;
            for (size_t i = 0; i < a->args.size(); ++i)
                if (!exprEqual(a->args[i], b->args[i])) return false;
            return true;
        }
        default: return false;
    }
}

/* ====================================================================== */
/*  Condition codes                                                        */
/* ====================================================================== */

enum class CC { NONE, E, NE, L, LE, G, GE, B, BE, A, AE, S, NS, P, NP, O, NO };

CC jcc_of(unsigned id) {
    switch (id) {
        case X86_INS_JE:  return CC::E;  case X86_INS_JNE: return CC::NE;
        case X86_INS_JL:  return CC::L;  case X86_INS_JLE: return CC::LE;
        case X86_INS_JG:  return CC::G;  case X86_INS_JGE: return CC::GE;
        case X86_INS_JB:  return CC::B;  case X86_INS_JBE: return CC::BE;
        case X86_INS_JA:  return CC::A;  case X86_INS_JAE: return CC::AE;
        case X86_INS_JS:  return CC::S;  case X86_INS_JNS: return CC::NS;
        case X86_INS_JP:  return CC::P;  case X86_INS_JNP: return CC::NP;
        case X86_INS_JO:  return CC::O;  case X86_INS_JNO: return CC::NO;
        default: return CC::NONE;
    }
}
CC setcc_of(unsigned id) {
    switch (id) {
        case X86_INS_SETE:  return CC::E;  case X86_INS_SETNE: return CC::NE;
        case X86_INS_SETL:  return CC::L;  case X86_INS_SETLE: return CC::LE;
        case X86_INS_SETG:  return CC::G;  case X86_INS_SETGE: return CC::GE;
        case X86_INS_SETB:  return CC::B;  case X86_INS_SETBE: return CC::BE;
        case X86_INS_SETA:  return CC::A;  case X86_INS_SETAE: return CC::AE;
        case X86_INS_SETS:  return CC::S;  case X86_INS_SETNS: return CC::NS;
        case X86_INS_SETP:  return CC::P;  case X86_INS_SETNP: return CC::NP;
        case X86_INS_SETO:  return CC::O;  case X86_INS_SETNO: return CC::NO;
        default: return CC::NONE;
    }
}
CC cmovcc_of(unsigned id) {
    switch (id) {
        case X86_INS_CMOVE:  return CC::E;  case X86_INS_CMOVNE: return CC::NE;
        case X86_INS_CMOVL:  return CC::L;  case X86_INS_CMOVLE: return CC::LE;
        case X86_INS_CMOVG:  return CC::G;  case X86_INS_CMOVGE: return CC::GE;
        case X86_INS_CMOVB:  return CC::B;  case X86_INS_CMOVBE: return CC::BE;
        case X86_INS_CMOVA:  return CC::A;  case X86_INS_CMOVAE: return CC::AE;
        case X86_INS_CMOVS:  return CC::S;  case X86_INS_CMOVNS: return CC::NS;
        /* O/NO/P/NP were MISSING: an unmodeled cmov falls through to the
         * "unmodeled op that writes a register" path, which defines the dest as an
         * opaque `__cmovo(x)` intrinsic — a PHANTOM call that silently drops the
         * conditional move (the overflow-checked abs `x<0 ? -x : x` lowers to
         * `neg; cmovo`). setcc_of already maps all four. */
        case X86_INS_CMOVO:  return CC::O;  case X86_INS_CMOVNO: return CC::NO;
        case X86_INS_CMOVP:  return CC::P;  case X86_INS_CMOVNP: return CC::NP;
        default: return CC::NONE;
    }
}
CC negate_cc(CC c) {
    switch (c) {
        case CC::E:  return CC::NE; case CC::NE: return CC::E;
        case CC::L:  return CC::GE; case CC::GE: return CC::L;
        case CC::G:  return CC::LE; case CC::LE: return CC::G;
        case CC::B:  return CC::AE; case CC::AE: return CC::B;
        case CC::A:  return CC::BE; case CC::BE: return CC::A;
        case CC::S:  return CC::NS; case CC::NS: return CC::S;
        case CC::P:  return CC::NP; case CC::NP: return CC::P;
        case CC::O:  return CC::NO; case CC::NO: return CC::O;
        default: return CC::NONE;
    }
}

/* ====================================================================== */
/*  Statement IR (structured tree)                                         */
/* ====================================================================== */

enum class SK {
    Assign,     /* lhs = rhs;  (lhs is Var/Mem) */
    Call,       /* call();  (expr-statement holding a Call) */
    Return,     /* return rhs?; */
    Goto,       /* goto label; */
    Label,      /* label: */
    Comment,    /* /​* text *​/  (unmodeled instruction) */
};

struct Stmt {
    SK kind = SK::Comment;
    ExprP lhs, rhs;
    std::string label;
    bool ret_void = true;
    uint64_t addr = 0;
};

/* ====================================================================== */
/*  Instruction wrapper                                                    */
/* ====================================================================== */

struct Insn {
    uint64_t addr = 0;
    uint32_t size = 0;
    unsigned id = 0;
    std::string mnem;
    std::string ops;
    cs_x86 x86;
    bool is_jcc = false;
    bool is_jmp = false;
    bool is_ret = false;
    bool is_call = false;
    uint64_t branch_target = 0;
    bool has_branch_target = false;
};

/* ====================================================================== */
/*  Basic block                                                            */
/* ====================================================================== */

struct Block {
    uint64_t addr = 0;
    int      id = -1;
    std::vector<int> insn_idx;
    std::vector<int> succ;
    std::vector<int> pred;
    int  fall = -1;
    int  taken = -1;
    CC   cc = CC::NONE;
    bool ends_jmp = false;
    bool ends_ret = false;
    bool ends_jcc = false;
    /* the terminating jcc was a redundant SSE NaN-guard (`jp T` paired with a
     * following lone `jne T`): its branch is dropped and the block falls through,
     * so exec_block must NOT re-derive a condition from the trailing jp. */
    bool drop_branch = false;

    /* jump-table switch dispatch (recovered) */
    bool is_switch = false;
    ExprP switch_var;                 /* the index expression */
    std::vector<int> case_succ;       /* case index -> successor block id */
    int default_succ = -1;
    /* a `cmp idx,K; ja default` guard that falls through to a switch block */
    bool is_switch_guard = false;
    int  guard_switch_blk = -1;       /* the switch block this guard precedes */

    /* statements emitted by symbolic execution (excludes the terminator) */
    std::vector<Stmt> stmts;
    /* branch condition selecting `taken` (true => goto taken) */
    ExprP cond;
    /* live-out register expressions at block exit (for phi resolution) */
    ExprP reg_out[R_COUNT];
    /* live-out high 64-bit lane of each XMM (for cross-block packed-SIMD lanes,
     * e.g. a loop-invariant broadcast set up in a preheader). */
    ExprP reg_out_hi[R_COUNT];
    /* live-out 4 packed-FLOAT lanes of each XMM + real flag, so a loop-invariant
     * broadcast (`shufps xmm,xmm,0` in a preheader) survives into the loop body
     * where the packed-float op (mulps/addps) consumes it. */
    ExprP reg_out_f[R_COUNT][4];
    bool  reg_out_f_real[R_COUNT] = {false};
    /* live-out 4 packed-INT lanes of each XMM + real flag (the packed-int analog:
     * a `movd;pshufd` broadcast in the guard block survives into the SSE body). */
    ExprP reg_out_i[R_COUNT][4];
    bool  reg_out_i_real[R_COUNT] = {false};
    /* live-out "this wide (ymm/zmm) register still holds the value loaded from
     * this address" fact. Lets a jump-table-unrolled memcpy — whose load and
     * store land in different basic blocks — still be modeled as a real chunked
     * copy instead of an opaque __vmovdqu(). Carried across a block edge only
     * when every predecessor agrees (see the entry_vla merge). */
    ExprP reg_out_vla[R_COUNT];
    /* live-out broadcast/zero/ones FILL of a wide register (value + element size),
     * so a jump-table-unrolled memset — fill set up in one block, streamed out in
     * others — still models as a real fill. Carried across a block edge only when
     * every predecessor agrees on both value and element size (see entry_vfill). */
    ExprP reg_out_vfill[R_COUNT];
    int   reg_out_vfill_esz[R_COUNT] = {0};
    /* return value expression (rax at a ret), if any */
    ExprP ret_value;
    bool  has_ret_value = false;
    /* untruncated rax expression at the ret (for late return-type recovery) */
    ExprP ret_raw;
    /* tail-call: `jmp <func>` rendered as `return func(args);` (or `func(args);`
     * when the function returns void) */
    ExprP tail_call;
};

/* ====================================================================== */
/*  Function signature table (prepass)                                     */
/* ====================================================================== */

struct FuncSig {
    int  param_count = 0;   /* 0..4 params (integer + float positions) */
    /* MSVC x64 va_start: a variadic callee homes ALL FOUR integer arg registers to their
     * shadow-space slots in the prologue -- rcx->[rsp+8], rdx->[rsp+0x10], r8->[rsp+0x18],
     * r9->[rsp+0x20] -- so va_arg can walk them as one array. A NON-variadic function homes
     * only the parameters it actually has, and /O2 usually homes none at all, which is what
     * makes all-four a signature rather than a guess.
     * Without this the engine has no arity for such a callee, falls back to "all four arg
     * registers are live", and prints whatever residue they held:
     *     fun_00001310("[NullWare] Game module found at 0x%p\n", v2, 4, 0)
     * one %p, three arguments. See trim_format_args(). */
    bool is_variadic = false;
    /* This function NEVER RETURNS: it contains no `ret` at all and its range ends in a trap
     * (int3/ud2). A caller's code after such a call is UNREACHABLE, and today we print it:
     *     fun_00005ef0();     <- never returns
     *     fun_00005e60();     <- dead
     *     return 0;           <- dead
     * The trap requirement is not decoration -- "no ret" alone is also what a function with
     * WRONG BOUNDS looks like, and claiming that one never returns would delete live code.
     * Filled by build_sig_table; consumed by emit_stmts. */
    bool is_noreturn = false;
    /* The Win32 type this function RETURNS, propagated across the call graph. A local wrapper
     * that hands back an API's result returns that API's type, and so does a wrapper of that
     * wrapper -- which is the only way `HMODULE dll = GetDllBase();` can be recovered, since
     * the caller never sees GetModuleHandleW at all. Empty = say nothing.
     * Filled by the fixpoint at the end of build_sig_table, off ret_call_target. */
    std::string ret_api;
    unsigned char float_mask = 0; /* bit p set => param position p is an XMM float/double arg */
    unsigned char double_mask = 0; /* bit p set (within float_mask) => that arg is DOUBLE (8B), else float (4B) */
    unsigned char float_typed_mask = 0; /* float params whose scalar WIDTH is known (4/8) — safe to type in a proto */
    /* CROSS-FUNCTION POINTER PARAMS: bit p set => integer arg-register p (rcx/rdx/r8/r9) is
     * DEREFERENCED inside the callee (used as the base of a real load/store, read-before-write)
     * before it is written. A dereferenced arg IS a pointer (or NULL) at every call site, which
     * the CALLER usually cannot see locally — so we propagate it: the caller's argument local is
     * typed a pointer instead of `long long`. ptr_param_w[p] is the access width at the deref (the
     * pointee-size hint: `mov al,[rcx]` -> char*, `mov rax,[rcx]` -> long long*). Filled by
     * build_sig_table, consumed at call sites. DS_NO_PTRPARAM disables. */
    unsigned char ptr_param_mask = 0;
    unsigned char ptr_param_w[4] = {0,0,0,0};
    int  ret_kind = 1;      /* 0 void, 1 int, 2 long long, 3 float, 4 double */
    bool ret_byte = false;  /* return is a byte (bool/char): the closest rax write
                             * to a ret is byte-width al WITHOUT zero-extension —
                             * the `xor al,al`/`mov al,..` bool-in-al contract. */
    /* Return-provenance, used by the void fixpoint below: a function whose only
     * return evidence is a call result (never a deliberate const/computed base
     * case) is void when that callee resolves void — or is itself, a pure
     * self-recursion with no base value (quicksort_range/heapify). */
    bool ret_only_from_call = false;
    bool saw_real_value_ret = false;
    bool saw_prior_call = false;  /* a non-tail call happened before the tail jmp */
    uint64_t ret_call_target = 0;
    /* LOCK RECOVERY: this function is a one-call WRAPPER around a lock primitive
     * (1 acquire, 2 release), so a caller can report the guarded region even though
     * the raw Enter/LeaveCriticalSection is a thunk away. The CRT's __acrt_lock(n)
     * idiom (`return EnterCriticalSection(&tab + n*0x28)`) puts essentially every
     * real lock behind such a thunk — keyed on the API name alone the match is
     * dead code on real binaries. */
    int lock_kind = 0;
};

/* ====================================================================== */
/*  The decompiler core                                                    */
/* ====================================================================== */

/* forward decl: defined after the class; used by detect_stack_params/detect_float_params */
static int fp_scalar_width(unsigned id);


struct Decompiler {
    /* ---- class body: topical sections (pure text partition, see decomp/) ---- */
#include "decomp/01_naming_reads.inc"
#include "decomp/02_rtti_vtable.inc"
#include "decomp/03_prologue_frame.inc"
#include "decomp/04_params.inc"
#include "decomp/05_types.inc"
#include "decomp/06_x87_fpu.inc"
#include "decomp/07_nullconst_backstop.inc"
#include "decomp/08_aggregates.inc"
#include "decomp/09_structs.inc"
#include "decomp/10_operator_new.inc"
#include "decomp/11_slots_simd_lanes.inc"
#include "decomp/12_flags_cond.inc"
#include "decomp/13_lift_insn.inc"
#include "decomp/14_lift_support.inc"
#include "decomp/15_idioms_api.inc"
#include "decomp/16_globals_phis.inc"
#include "decomp/17_render.inc"
#include "decomp/18_cfg_loops.inc"
#include "decomp/19_emit_structure.inc"
#include "decomp/20_loop_sinks.inc"
    std::string collapse_else_if(const std::string& body) {
        if (std::getenv("DS_NO_ELSEIF")) return body;
        std::vector<std::string> L;
        { size_t p = 0; while (p <= body.size()) { size_t nl = body.find('\n', p);
            if (nl == std::string::npos) { if (p < body.size()) L.push_back(body.substr(p)); break; }
            L.push_back(body.substr(p, nl - p)); p = nl + 1; } }
        auto ind_of = [](const std::string& s){ size_t i = 0; while (i < s.size() && s[i] == ' ') ++i; return (int)i; };
        bool changed = true; int guard = 0;
        while (changed && guard++ < 100000) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            for (size_t i = 0; i + 1 < L.size(); ++i) {
                int I = ind_of(L[i]);
                if (L[i] != std::string(I, ' ') + "} else {") continue;
                size_t j = i + 1;
                while (j < L.size() && L[j].find_first_not_of(" \t") == std::string::npos) ++j;
                if (j >= L.size() || ind_of(L[j]) != I + 4) continue;
                std::string inner = L[j].substr(I + 4);
                if (inner.rfind("if (", 0) != 0 || inner.empty() || inner.back() != '{') continue;
                /* find close of the else block. `} else {` nets to 0 (the leading `}`
                 * closes the prior block, the trailing `{` opens the else), so seed
                 * depth=1 for that open brace and scan from the NEXT line. */
                int depth = 1; size_t close = std::string::npos;
                for (size_t k = i + 1; k < L.size(); ++k) { depth += net_braces_ol(L[k]); if (depth == 0) { close = k; break; } }
                if (close == std::string::npos || L[close] != std::string(I, ' ') + "}") continue;
                /* the inner if (+ its own else chain) must span the WHOLE else block */
                int d2 = 0; size_t innerclose = std::string::npos;
                for (size_t k = j; k < close; ++k) { d2 += net_braces_ol(L[k]); if (d2 == 0) { innerclose = k; break; } }
                if (innerclose != close - 1) continue;   /* >1 statement in the else block */
                /* transform */
                L[i] = std::string(I, ' ') + "} else " + inner;      /* `} else if (C) {` */
                for (size_t k = j + 1; k < close; ++k)               /* dedent inner body/chain by 4 */
                    if (L[k].size() >= 4 && L[k].compare(0, 4, "    ") == 0) L[k] = L[k].substr(4);
                L.erase(L.begin() + close);
                L.erase(L.begin() + j);
                changed = true; break;
            }
        }
        std::string out; for (auto& s : L) { out += s; out += "\n"; } return out;
    }

    /* Match the `)` for the `(` at s[open], skipping string/char literals. */
    static int match_paren_ol(const std::string& s, size_t open) {
        int d = 0; bool instr = false, inch = false;
        for (size_t i = open; i < s.size(); ++i) {
            char c = s[i];
            if (instr || inch) { if (c=='\\'){++i;continue;} if ((instr&&c=='"')||(inch&&c=='\'')) instr=inch=false; continue; }
            if (c=='"') instr=true; else if (c=='\'') inch=true;
            else if (c=='(') ++d; else if (c==')') { if (--d==0) return (int)i; }
        }
        return -1;
    }
    /* B5: collapse a sole-child guard nest `if (A) { if (B) { ... } }` (outer if has NO
     * else, inner if is the outer's ONLY statement and has NO else) into
     * `if (A && B) { ... }`. Semantics-identical (both require A AND B; neither has an
     * else path). Pure text reshaping — a bug yields non-compiling C, caught by the
     * gate. Iterates so `if(A){if(B){if(C){}}}` folds fully. Gated DS_NO_ANDGUARD. */
    std::string collapse_and_guards(const std::string& body) {
        if (std::getenv("DS_NO_ANDGUARD")) return body;
        std::vector<std::string> L;
        { size_t p = 0; while (p <= body.size()) { size_t nl = body.find('\n', p);
            if (nl == std::string::npos) { if (p < body.size()) L.push_back(body.substr(p)); break; }
            L.push_back(body.substr(p, nl - p)); p = nl + 1; } }
        auto ind_of = [](const std::string& s){ size_t i=0; while(i<s.size()&&s[i]==' ')++i; return (int)i; };
        auto if_cond = [&](const std::string& s, int I, std::string& cond) -> bool {
            /* s == `<I>if (COND) {` -> extract COND */
            std::string t = s.substr(I);
            if (t.rfind("if (", 0) != 0 || t.empty() || t.back() != '{') return false;
            size_t op = I + 3;                       /* the '(' after `if ` */
            if (op >= s.size() || s[op] != '(') return false;
            int cp = match_paren_ol(s, op);
            if (cp < 0) return false;
            /* everything after the matched `)` must be just ` {` */
            std::string after = s.substr(cp + 1);
            if (after != " {") return false;
            cond = s.substr(op + 1, cp - op - 1);
            return !cond.empty();
        };
        bool changed = true; int guard = 0;
        while (changed && guard++ < 100000) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            for (size_t i = 0; i + 1 < L.size(); ++i) {
                int I = ind_of(L[i]);
                std::string A;
                if (!if_cond(L[i], I, A)) continue;
                /* find the outer if's close via brace depth */
                int depth = 0; size_t close = std::string::npos;
                for (size_t k = i; k < L.size(); ++k) { depth += net_braces_ol(L[k]); if (depth == 0) { close = k; break; } }
                if (close == std::string::npos || L[close] != std::string(I,' ') + "}") continue;  /* outer has else -> `} else {` */
                size_t j = i + 1;
                while (j < close && L[j].find_first_not_of(" \t") == std::string::npos) ++j;
                if (j >= close || ind_of(L[j]) != I + 4) continue;
                std::string B;
                if (!if_cond(L[j], I + 4, B)) continue;
                /* inner if must span the whole outer body and have NO else: its close is
                 * exactly close-1 and no `else` at indent I+4 appears inside. */
                if (L[close-1] != std::string(I+4,' ') + "}") continue;
                bool inner_else = false;
                for (size_t k = j+1; k < close-1; ++k) {
                    int ik = ind_of(L[k]);
                    if (ik <= I+4 && (L[k].substr(ik).rfind("} else",0)==0 || L[k].substr(ik).rfind("else",0)==0)) { inner_else = true; break; }
                }
                if (inner_else) continue;
                /* verify inner-if brace depth returns to 0 exactly at close-1 */
                int d2 = 0; size_t ic = std::string::npos;
                for (size_t k = j; k < close; ++k) { d2 += net_braces_ol(L[k]); if (d2 == 0) { ic = k; break; } }
                if (ic != close - 1) continue;
                auto wrap = [](const std::string& s){ return s.find("||") != std::string::npos ? "(" + s + ")" : s; };
                L[i] = std::string(I,' ') + "if (" + wrap(A) + " && " + wrap(B) + ") {";
                for (size_t k = j+1; k + 1 < close; ++k)             /* dedent inner body by 4 */
                    if (L[k].size() >= 4 && L[k].compare(0,4,"    ") == 0) L[k] = L[k].substr(4);
                L.erase(L.begin() + (close - 1));                    /* inner close */
                L.erase(L.begin() + j);                              /* inner header */
                changed = true; break;
            }
        }
        std::string out; for (auto& s : L) { out += s; out += "\n"; } return out;
    }

    /* fallback: pure goto-CFG emission (always correct). */
    /* Verify every `goto L;` in `body` has a matching `L:` definition. Returns
     * false if a dangling goto exists (so the caller can fall back). */
    /* Scan emitted C `body` for the set of labels referenced by `goto L;` and
     * the set defined by `L:` lines. Shared by labels_consistent() and
     * dangling_label_blocks() so both agree on exactly what counts as a label.
     *
     * A definition is only recognised when `L_` begins an identifier token, i.e.
     * the preceding char is not part of an identifier. Without that boundary
     * check a substring `L_` embedded in a longer name (e.g. a future variable
     * `vL_3:` or a cast) could be mis-counted as a label definition and mask a
     * genuinely dangling goto, letting non-compiling C slip past the consistency
     * gate. block_label() only ever emits `L_<hex>`, so the token always starts
     * with `L_`. */
    void scan_labels(const std::string& body,
                     std::set<std::string>& defined,
                     std::set<std::string>& referenced) {
        size_t pos = 0;
        while ((pos = body.find("goto ", pos)) != std::string::npos) {
            size_t s = pos + 5;
            size_t e2 = body.find(';', s);
            if (e2 == std::string::npos) break;
            std::string lab = body.substr(s, e2 - s);
            /* trim spaces */
            while (!lab.empty() && (lab.back()==' '||lab.back()=='\t')) lab.pop_back();
            referenced.insert(lab);
            pos = e2;
        }
        pos = 0;
        while ((pos = body.find("L_", pos)) != std::string::npos) {
            /* require a token boundary before `L_` so embedded substrings are
             * not mistaken for a label definition */
            bool boundary = (pos == 0);
            if (!boundary) {
                char prev = body[pos - 1];
                boundary = !(isalnum((unsigned char)prev) || prev == '_');
            }
            size_t e2 = pos;
            while (e2 < body.size() &&
                   (isalnum((unsigned char)body[e2]) || body[e2]=='_')) e2++;
            /* a label definition looks like `L_xxxx:` at some indentation */
            if (boundary && e2 < body.size() && body[e2] == ':')
                defined.insert(body.substr(pos, e2 - pos));
            pos = e2 > pos ? e2 : pos + 1;
        }
    }

    /* True if any `L_xxxx:` label is DEFINED more than once. scan_labels() uses a
     * set and so is blind to this, but C forbids two definitions of the same label
     * in one function (C2045). A structured body can emit a duplicate when a block
     * is replicated (tail duplication / a degenerate empty landing block that gets
     * inlined at several sites) yet still keeps its address-derived label at each
     * copy. Such a body is label-"consistent" (every goto resolves) but does NOT
     * compile, so labels_consistent() must reject it and force the goto-CFG
     * fallback, which emits every block exactly once. */
    bool has_duplicate_label_defs(const std::string& body) {
        std::map<std::string,int> def_count;
        size_t pos = 0;
        while ((pos = body.find("L_", pos)) != std::string::npos) {
            bool boundary = (pos == 0);
            if (!boundary) {
                char prev = body[pos - 1];
                boundary = !(isalnum((unsigned char)prev) || prev == '_');
            }
            size_t e2 = pos;
            while (e2 < body.size() &&
                   (isalnum((unsigned char)body[e2]) || body[e2]=='_')) e2++;
            if (boundary && e2 < body.size() && body[e2] == ':')
                if (++def_count[body.substr(pos, e2 - pos)] > 1) return true;
            pos = e2 > pos ? e2 : pos + 1;
        }
        return false;
    }

    /* Final safety net: drop DUPLICATE label-definition lines, keeping the first.
     *
     * Even the goto-CFG fallback can emit the same label twice when two distinct CFG
     * blocks share an address (block_label is address-derived, so they collide) -- a
     * degenerate case that surfaces only for a few functions and only when global
     * decompile state nudges the block split (dumping the function in isolation is
     * clean). labels_consistent() rejects the structured attempt for this, but the
     * fallback re-emits the same collision, so a hard C2045 ("label redefined")
     * survives. A pure `L_xxxx:;` label line is always on its own line; deleting the
     * 2nd+ definition (the label token only -- the code that followed it still runs by
     * fall-through) leaves valid C: every `goto L_xxxx;` resolves to the one remaining
     * definition. Applied unconditionally to the final body so the output ALWAYS
     * compiles, whatever produced the duplicate. */
    std::string dedupe_label_defs(const std::string& body) {
        if (!has_duplicate_label_defs(body)) return body;   /* common path: no-op */
        std::set<std::string> seen;
        std::string out; out.reserve(body.size());
        size_t i = 0;
        while (i < body.size()) {
            size_t eol = body.find('\n', i);
            size_t len = (eol == std::string::npos) ? body.size() - i : eol - i + 1;
            std::string line = body.substr(i, len);
            i += len;
            size_t a = line.find_first_not_of(" \t");
            size_t z = line.find_last_not_of(" \t\r\n");
            std::string core = (a == std::string::npos) ? "" : line.substr(a, z - a + 1);
            /* a bare label-definition line: `<ident>:;` (block labels are `L_xxxx:;`) */
            if (core.size() > 2 && core.compare(core.size() - 2, 2, ":;") == 0) {
                std::string lab = core.substr(0, core.size() - 2);
                bool ident = !lab.empty() &&
                    (isalpha((unsigned char)lab[0]) || lab[0] == '_');
                for (size_t k = 1; ident && k < lab.size(); ++k)
                    if (!(isalnum((unsigned char)lab[k]) || lab[k] == '_')) ident = false;
                if (ident && !seen.insert(lab).second) continue;   /* drop the redefinition */
            }
            out += line;
        }
        return out;
    }

    bool labels_consistent(const std::string& body) {
        std::set<std::string> defined, referenced;
        scan_labels(body, defined, referenced);
        for (auto& r : referenced)
            if (r.rfind("L_",0)==0 && !defined.count(r)) return false;
        if (has_duplicate_label_defs(body)) return false;
        return true;
    }

    /* Remove `L_xxxx:;` lines that no `goto` targets — dead labels. They arise
     * from empty fall-through blocks (e.g. a collapsed SSE NaN-guard leaves the
     * jp block empty but still labeled) and from join blocks that ended up reached
     * only by fall-through. Removing an unreferenced label is always valid C, so
     * this is a safe, general cosmetic cleanup applied to the final body. */
    std::string prune_dead_labels(const std::string& body) {
        std::set<std::string> defined, referenced;
        scan_labels(body, defined, referenced);
        std::set<std::string> dead;
        for (auto& d : defined) if (!referenced.count(d)) dead.insert(d);
        if (dead.empty()) return body;
        std::string out; out.reserve(body.size());
        size_t i = 0;
        while (i < body.size()) {
            size_t eol = body.find('\n', i);
            size_t len = (eol == std::string::npos) ? body.size() - i : eol - i + 1;
            std::string line = body.substr(i, len);
            i += len;
            /* trim to the line's core token to test for a bare `L_xxxx:;` */
            size_t a = line.find_first_not_of(" \t");
            size_t z = line.find_last_not_of(" \t\r\n");
            std::string core = (a == std::string::npos) ? "" : line.substr(a, z - a + 1);
            if (core.size() > 2 && core.rfind("L_", 0) == 0 &&
                core.compare(core.size() - 2, 2, ":;") == 0 &&
                dead.count(core.substr(0, core.size() - 2))) {
                continue;   /* drop the dead-label line */
            }
            out += line;
        }
        return out;
    }

    /* Scope-aware unreachable-code elimination on the emitted C `body`.
     *
     * The recursive structurer can leave a statement immediately after an
     * unconditional control transfer (`return`/`goto`/`break`/`continue`) within
     * the same brace scope — most importantly a trailing `goto L_x;` after a
     * `return` where L_x was duplicated inline (so no `L_x:` label exists). That
     * single dead goto makes labels_consistent() fail and reverts the WHOLE
     * function to a loop-switch state machine, even though the structured form is
     * otherwise complete and correct. Removing statements that provably cannot be
     * reached (they follow an unconditional transfer, before the scope closes or a
     * jump target intervenes) is always semantics-preserving.
     *
     * Conservative and depth-safe: we only DROP lines that contain no braces (the
     * dead `goto;`/assignment case). Any line that opens/closes a scope, a `}`, a
     * label (`L_x:`/`case`/`default:` — reachable via jump), stops the dead run so
     * brace-depth tracking never desyncs. */
    static bool is_uncond_transfer_line(const std::string& t) {
        if (t == "break;" || t == "continue;") return true;
        if (t.rfind("goto ", 0) == 0) return true;
        /* require a word boundary after `return` so an identifier like
         * `returnValue = ...` is never mistaken for a return statement */
        if (t.rfind("return", 0) == 0)
            return t.size() == 6 || t[6] == ' ' || t[6] == ';';
        return false;
    }
    std::string strip_unreachable_after_terminator(const std::string& body) {
        /* A label only anchors reachable code if some `goto` actually targets it;
         * an UNreferenced `L_xxxx:;` after a terminator is itself dead (a spurious
         * landing block), so it must NOT end the dead run — otherwise the dead
         * `goto` it precedes survives (the exact defect that reverts the recursive
         * tree-walk to a state machine). `case`/`default:` are always reachable
         * (switch dispatch). */
        std::set<std::string> defined, referenced;
        scan_labels(body, defined, referenced);
        auto is_reachable_target = [&](const std::string& t) -> bool {
            if (t.rfind("case ", 0) == 0 || t == "default:") return true;
            if (t.rfind("L_", 0) == 0) {
                size_t c = t.find(':');
                if (c != std::string::npos) return referenced.count(t.substr(0, c)) > 0;
            }
            return false;
        };
        std::string out; out.reserve(body.size());
        bool dead = false;
        size_t i = 0, n = body.size();
        while (i < n) {
            size_t eol = body.find('\n', i);
            size_t len = (eol == std::string::npos) ? n - i : eol - i + 1;
            std::string line = body.substr(i, len);
            i += len;
            size_t a = line.find_first_not_of(" \t");
            size_t z = line.find_last_not_of(" \t\r\n");
            std::string core = (a == std::string::npos) ? "" : line.substr(a, z - a + 1);
            bool has_brace = core.find('{') != std::string::npos ||
                             core.find('}') != std::string::npos;
            if (dead) {
                if (core.empty()) { out += line; continue; }   /* keep blank, stay dead */
                /* End the dead run only at a scope boundary or a genuinely
                 * reachable jump target; drop everything else in between. */
                if (has_brace || is_reachable_target(core))
                    dead = false;
                else
                    continue;   /* provably unreachable — drop it */
            }
            out += line;
            if (!has_brace && is_uncond_transfer_line(core))
                dead = true;
        }
        return out;
    }

    /* Collect the set of block ids whose label is referenced by a `goto`/`if(..)
     * goto` in `body` but never defined (`L_xxxx:`). These are the dangling
     * targets that make labels_consistent() fail. Mapping a label string back to
     * a block id lets the repair pass emit a labeled landing region for exactly
     * those blocks instead of discarding the whole structured function. */
    std::vector<int> dangling_label_blocks(const std::string& body) {
        std::set<std::string> defined, referenced;
        scan_labels(body, defined, referenced);
        /* index blocks by their label string once */
        std::map<std::string,int> by_label;
        for (auto& b : blocks) by_label[block_label(b.id)] = b.id;
        std::vector<int> out_ids;
        for (auto& r : referenced) {
            if (r.rfind("L_",0) != 0 || defined.count(r)) continue;
            auto it = by_label.find(r);
            if (it != by_label.end()) out_ids.push_back(it->second);
        }
        return out_ids;
    }

    void emit_goto_cfg(std::string& dst) {
        std::vector<int> order(blocks.size());
        for (size_t i = 0; i < blocks.size(); ++i) order[i] = (int)i;
        std::sort(order.begin(), order.end(),
                  [&](int a, int c){ return blocks[a].addr < blocks[c].addr; });
        for (size_t oi = 0; oi < order.size(); ++oi) {
            int id = order[oi];
            Block& b = blocks[id];
            dst += block_label(id) + ":;\n";
            emit_stmts(id, dst);
            int nxt = (oi + 1 < order.size()) ? order[oi + 1] : -1;
            if (b.ends_ret) {
                dst += ind() + ret_text(id) + "\n";
            } else if (b.is_switch) {
                dst += ind() + "switch (" + switch_sel(b.switch_var ? b.switch_var : mkConst(0,4)) + ") {\n";
                indent_lvl++;
                for (size_t i = 0; i < b.case_succ.size(); ++i) {
                    if (b.case_succ[i] < 0) continue;
                    dst += ind() + "case " + std::to_string(i) + ": goto " +
                           block_label(b.case_succ[i]) + ";\n";
                }
                indent_lvl--;
                dst += ind() + "}\n";
                if (b.default_succ >= 0)
                    dst += ind() + "goto " + block_label(b.default_succ) + ";\n";
            } else if (b.ends_jcc) {
                if (b.taken >= 0)
                    dst += ind() + "if (" + render_cond(b.cond ? b.cond : mkConst(1,4)) +
                           ") goto " + block_label(b.taken) + ";\n";
                if (b.fall >= 0 && b.fall != nxt)
                    dst += ind() + "goto " + block_label(b.fall) + ";\n";
            } else if (b.ends_jmp) {
                if (b.taken >= 0) {
                    if (b.taken != nxt) dst += ind() + "goto " + block_label(b.taken) + ";\n";
                } else dst += ind() + ret_text(id) + "\n";
            } else {
                if (b.fall >= 0 && b.fall != nxt)
                    dst += ind() + "goto " + block_label(b.fall) + ";\n";
                else if (b.fall < 0)
                    dst += ind() + ret_text(id) + "\n";
            }
        }
    }

    /* GUARANTEED goto-free emission of ANY CFG (reducible or irreducible) via a
     * loop-switch dispatch: `int __state = entry; while(1) switch(__state){...}`.
     * Each block is a `case <id>:`; `goto X` becomes `__state = X; break;` (the
     * outer-switch break re-enters the while), and a `ret`/tail-call exits the
     * loop. Böhm-Jacopini: this represents ANY control flow with ZERO gotos, because
     * the edges become DATA (the __state variable) instead of goto statements.
     *
     * OPT-IN ONLY (DS_FORCE_SM). It is NOT the default because it is strictly harder to
     * read than a few honest gotos: it flattens the whole function into a dispatch loop,
     * destroying the natural loops/ifs that structured correctly. Restored 2026-07-17 as
     * a user-selectable toggle -- "make every goto a state machine" vs "leave plain
     * gotos" -- after being removed as a mandatory pass. */
    void emit_state_machine(std::string& dst) {
        int entry = entry_block();
        dst += ind() + "int __state = " + std::to_string(entry) + ";\n";
        used_while_true = true;
        dst += ind() + "while (true) {\n";
        indent_lvl++;
        dst += ind() + "switch (__state) {\n";
        indent_lvl++;
        std::vector<int> order(blocks.size());
        for (size_t i = 0; i < blocks.size(); ++i) order[i] = (int)i;
        std::sort(order.begin(), order.end(),
                  [&](int a, int c){ return blocks[a].addr < blocks[c].addr; });
        for (int id : order) {
            Block& b = blocks[id];
            if (merged_blocks.count(id)) continue;   /* folded into a predecessor */
            dst += ind() + "case " + std::to_string(id) + ":\n";
            indent_lvl++;
            emit_stmts(id, dst);
            if (b.ends_ret) {
                dst += ind() + ret_text(id) + "\n";
            } else if (b.is_switch && b.switch_var) {
                dst += ind() + "switch (" + switch_sel(b.switch_var) + ") {\n";
                indent_lvl++;
                for (size_t i = 0; i < b.case_succ.size(); ++i) {
                    if (b.case_succ[i] < 0) continue;
                    dst += ind() + "case " + std::to_string(i) + ": __state = " +
                           std::to_string(b.case_succ[i]) + "; break;\n";
                }
                if (b.default_succ >= 0)
                    dst += ind() + "default: __state = " +
                           std::to_string(b.default_succ) + "; break;\n";
                indent_lvl--;
                dst += ind() + "}\n";
                dst += ind() + "break;\n";
            } else if (b.ends_jcc && b.taken >= 0 && b.fall >= 0) {
                dst += ind() + "__state = " + render(b.cond ? b.cond : mkConst(1, 4)) +
                       " ? " + std::to_string(b.taken) + " : " +
                       std::to_string(b.fall) + ";\n";
                dst += ind() + "break;\n";
            } else if (b.ends_jmp) {
                if (b.taken >= 0) {
                    dst += ind() + "__state = " + std::to_string(b.taken) + ";\n";
                    dst += ind() + "break;\n";
                } else dst += ind() + ret_text(id) + "\n";   /* tail / extern jmp */
            } else if (b.fall >= 0) {
                dst += ind() + "__state = " + std::to_string(b.fall) + ";\n";
                dst += ind() + "break;\n";
            } else {
                dst += ind() + ret_text(id) + "\n";
            }
            indent_lvl--;
        }
        indent_lvl--;
        dst += ind() + "}\n";   /* switch */
        indent_lvl--;
        dst += ind() + "}\n";   /* while(1) */
    }

    /* =================================================================== */
    /*  Type inference for declarations                                     */
    /* =================================================================== */

    /* Count reads of a named variable across an expression (LHS Mem address
     * counts as a read; a bare Var/Mem-store LHS does not). */
    int count_var_reads(const ExprP& e, const std::string& nm) {
        if (!e) return 0;
        int c = 0;
        if (e->kind == EK::Var && e->name == nm) c++;
        c += count_var_reads(e->a, nm) + count_var_reads(e->b, nm) +
             count_var_reads(e->c, nm);
        for (auto& ar : e->args) c += count_var_reads(ar, nm);
        return c;
    }
    int count_lhs_addr_reads(const ExprP& lhs, const std::string& nm) {
        if (!lhs) return 0;
        if (lhs->kind == EK::Mem) return count_var_reads(lhs->a, nm);
        return 0;   /* a plain Var/Mem destination is a write, not a read */
    }

    /* Remove assignments to a local/temp whose variable is never read anywhere
     * (and whose RHS has no call/side-effect). This deletes the param-home
     * copies `vN = aN;` MSVC /Od emits, and dead phi temps. Iterates to a fixed
     * point since deleting one store may make another store's reads disappear. */
    /* Tally EVERY variable read in an expression in a SINGLE tree walk, incrementing
     * reads[name] per Var node. Replaces the old `for each var: count_var_reads(e, var)`
     * (which re-walked the whole expression once PER variable — O(nodes * numVars)); this
     * is O(nodes). The result is identical on the keys dead_store_elim consults (it only
     * tests presence of an ASSIGNED var, which is always a real local), so the DSE
     * decisions — and thus the output — are byte-for-byte unchanged, just ~numVars faster.
     * (On fun_0004b530: numVars ~= 340, and dead_store_elim went 18s -> milliseconds.) */
    void tally_reads(const ExprP& e, std::map<std::string,int>& reads) {
        if (!e) return;
        if (e->kind == EK::Var) reads[e->name]++;
        tally_reads(e->a, reads); tally_reads(e->b, reads); tally_reads(e->c, reads);
        for (auto& ar : e->args) tally_reads(ar, reads);
    }
    /* Set-of-read-var-names analog of tally_reads, for the global-DSE liveness
     * sets. Same single-walk speedup: `for each var: count_var_reads(e,var)` ->
     * one tree walk. Inserting non-var_width names too is harmless — the drop
     * decision only tests var_width members, so the result is identical. */
    void insert_reads(const ExprP& e, std::set<std::string>& s) {
        if (!e) return;
        if (e->kind == EK::Var) s.insert(e->name);
        insert_reads(e->a, s); insert_reads(e->b, s); insert_reads(e->c, s);
        for (auto& ar : e->args) insert_reads(ar, s);
    }
    /* a Mem destination READS its address operand; a plain Var dest is a write. */
    void insert_lhs_addr_reads(const ExprP& lhs, std::set<std::string>& s) {
        if (lhs && lhs->kind == EK::Mem) insert_reads(lhs->a, s);
    }
    void dead_store_elim() {
        bool changed = true; int guard = 0;
        while (changed && guard++ < 16) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            /* tally reads of every var name (single walk per expression) */
            std::map<std::string,int> reads;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) {
                    tally_reads(s.rhs, reads);
                    /* a Mem destination READS its address operand; a plain Var
                     * destination is a write, not a read (matches count_lhs_addr_reads). */
                    if (s.lhs && s.lhs->kind == EK::Mem) tally_reads(s.lhs->a, reads);
                }
                tally_reads(b.cond, reads);
                tally_reads(b.ret_value, reads);
                tally_reads(b.ret_raw, reads);
                tally_reads(b.switch_var, reads);
                tally_reads(b.tail_call, reads);
            }
            for (auto& b : blocks) {
                std::vector<Stmt> keep;
                keep.reserve(b.stmts.size());
                for (auto& s : b.stmts) {
                    bool drop = false;
                    /* An unread assignment whose RHS is a PURE computation is dead, even
                     * when that RHS contains an intrinsic (`v = _rotl(x,n)`, `v = __umulh(..)`)
                     * — dropping it cannot change behaviour. has_impure_call (not has_call)
                     * still pins anything that writes memory or may not return. */
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                        !has_impure_call(s.rhs)) {
                        const std::string& nm = s.lhs->name;
                        if (reads.find(nm) == reads.end()) { drop = true; }
                    }
                    if (drop) changed = true;
                    else keep.push_back(s);
                }
                b.stmts.swap(keep);
            }
        }
    }

    /* Local (within-block) dead-store elimination: `v = X; ... ; v = Y;` where
     * v is not read between the two writes drops the first (`v = X`). This kills
     * the spurious `v2 = a1; v2 = 0;` double-init MSVC /Od emits when seeding an
     * accumulator from its stack-home slot before zeroing it. Conservative: the
     * dead RHS must be side-effect free, and we stop scanning at the first
     * statement that could read v (directly, through memory, or via a call). */
    void local_dead_store_elim() {
        for (auto& b : blocks) {
            std::vector<bool> drop(b.stmts.size(), false);
            for (size_t i = 0; i < b.stmts.size(); ++i) {
                const Stmt& s = b.stmts[i];
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var)
                    continue;
                if (has_call(s.rhs)) continue;        /* RHS may have side effects */
                const std::string nm = s.lhs->name;
                /* the first assignment is dead if a later statement in this block
                 * re-writes v without any intervening read of v. */
                for (size_t j = i + 1; j < b.stmts.size(); ++j) {
                    const Stmt& t = b.stmts[j];
                    /* a read of v anywhere kills the search (store is live) */
                    int reads = count_var_reads(t.rhs, nm) +
                                count_lhs_addr_reads(t.lhs, nm);
                    if (reads) break;
                    /* a plain overwrite of v before any read => first store dead */
                    if (t.kind == SK::Assign && t.lhs && t.lhs->kind == EK::Var &&
                        t.lhs->name == nm) {
                        drop[i] = true;
                        break;
                    }
                    /* a call or a store through memory might observe v only if v
                     * is address-taken; our locals are not, so we can continue. */
                }
            }
            std::vector<Stmt> keep;
            for (size_t i = 0; i < b.stmts.size(); ++i)
                if (!drop[i]) keep.push_back(b.stmts[i]);
            b.stmts.swap(keep);
        }
    }

    /* Global (cross-block) dead-store elimination via named-variable liveness.
     *
     * `local_dead_store_elim` only sees within one block and `dead_store_elim`
     * only drops vars never read *anywhere*; neither removes the very common
     * argument-home copy `v2 = a1;` that MSVC /Od emits at function entry when
     * v2 is overwritten on every path before its (later) use. Such a store is
     * dead because v2 is not live immediately after it.
     *
     * We compute classic backward liveness over named locals/temps (vN/tN and
     * the renamed params), then delete an assignment `v = X` (X side-effect
     * free, v a tracked Var) whenever v is not live at the point right after the
     * store. Conservative: only Var (not Mem) destinations, and a var that is
     * ever address-taken (`&v`) is treated as always-live so we never drop a
     * store whose value could escape. Iterates to a fixpoint since removing one
     * store can make an earlier one dead. */
    /* Replace every subtree of `e` structurally equal to `pat` with a reference
     * to the variable `var`. Used to fix the fused dec/jnz off-by-one. */
    void replace_subexpr(ExprP& e, const ExprP& pat, const std::string& var, int w) {
        if (!e || !pat) return;
        if (e->kind != EK::Var && exprEqual(e, pat)) { e = mkVar(var, w); return; }
        replace_subexpr(e->a, pat, var, w);
        replace_subexpr(e->b, pat, var, w);
        replace_subexpr(e->c, pat, var, w);
        for (auto& ar : e->args) replace_subexpr(ar, pat, var, w);
    }

    /* Fix the fused `dec/sub reg,k; jcc` (and `inc/add`) idiom that pervades /O2
     * loops. The branch flag tests the RESULT of the arithmetic, which the block
     * already materialized as its last statement `t = <expr>` (e.g. t2 = t2 - 1).
     * Rendered sequentially, a condition that re-uses `<expr>` evaluates it on the
     * POST-assignment value: `t2 = t2 - 1; if (t2 - 1 != 0)` tests t2-2, an
     * off-by-one in the loop trip count. Replace the re-evaluated expression in
     * the branch with the just-assigned variable -> `if (t2 != 0)`. Only fires
     * when the matching assignment is the block's final statement (nothing runs
     * between it and the branch), so it is exact. The /Od corpus never hits this
     * (its loops use a separate `cmp` that re-reads the slot as the bare var). */
    void canonicalize_branch_after_assign() {
        for (auto& b : blocks) {
            if (!b.cond) continue;
            const Stmt* last = nullptr;
            for (int i = (int)b.stmts.size() - 1; i >= 0; --i) {
                const Stmt& s = b.stmts[i];
                if (s.kind == SK::Comment) continue;
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                    s.rhs && s.rhs->kind != EK::Var && s.rhs->kind != EK::Const &&
                    !has_call(s.rhs))
                    last = &s;
                break;   /* only the genuinely-last statement qualifies */
            }
            if (!last) continue;
            replace_subexpr(b.cond, last->rhs, last->lhs->name,
                            last->lhs->width ? last->lhs->width : 4);
        }
    }

    /* Coalesce phi-split / register-move locals into ONE name. After copy_propagate,
     * the residual noise is MULTI-use copies (`t9=t5; …t9…; …t5…`) and phi lowerings
     * (`tN=<pred value>` per predecessor) — the SAME logical variable under several
     * names. Two names are merged ONLY when their live ranges do NOT interfere
     * (classic Chaitin graph + copy exception): the class then shares one physical
     * variable, sound iff no two members are simultaneously live with distinct values.
     * PHYSICAL rename (Expr::name + type maps) so AUTONAME later aliases the canonical.
     * Only bare `x = y` copies between same-decl_type, non-address-taken scalar v/t
     * locals are candidates. Gated by DS_NO_COALESCE. */
    void coalesce_locals() {
        if (std::getenv("DS_NO_COALESCE")) return;
        auto ok = [&](const std::string& nm) -> bool {
            if (nm.size() < 2 || (nm[0] != 'v' && nm[0] != 't')) return false;
            for (size_t i = 1; i < nm.size(); ++i) if (nm[i] < '0' || nm[i] > '9') return false;
            return !array_locals.count(nm);
        };
        std::set<std::string> addr; collect_addr_taken(addr);
        /* (1) candidate copies x = y */
        struct C { std::string x, y; };
        std::vector<C> cand;
        for (auto& b : blocks) for (auto& s : b.stmts)
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                s.rhs && s.rhs->kind == EK::Var && s.lhs->name != s.rhs->name) {
                const std::string& x = s.lhs->name; const std::string& y = s.rhs->name;
                if (ok(x) && ok(y) && !addr.count(x) && !addr.count(y) && decl_type(x) == decl_type(y))
                    cand.push_back({x, y});
            }
        if (cand.empty()) return;
        std::set<std::string> uni; for (auto& c : cand) { uni.insert(c.x); uni.insert(c.y); }
        /* (2) per-name liveness over the candidate universe (backward dataflow) */
        size_t n = blocks.size(); std::map<int,size_t> ix; for (size_t i=0;i<n;++i) ix[blocks[i].id]=i;
        std::vector<std::set<std::string>> lin(n), lout(n);
        /* single-walk collection of uni-vars read by an expr: O(expr), not O(uni*expr).
         * (The naive per-name count_var_reads made this pass hang on large functions.) */
        auto uses = [&](const ExprP& e, std::set<std::string>& S){
            std::function<void(const ExprP&)> w = [&](const ExprP& x){
                if (!x) return;
                if (x->kind == EK::Var && uni.count(x->name)) S.insert(x->name);
                w(x->a); w(x->b); w(x->c); for (auto& a : x->args) w(a);
            };
            w(e);
        };
        auto killdef = [&](Stmt& s, std::set<std::string>& cur){
            /* a Var-def kills the name then reads its rhs; any other stmt (incl. a
             * Mem store `*(T*)(x+k)=y`) reads BOTH sides (the address x and the value). */
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) {
                cur.erase(s.lhs->name); uses(s.rhs, cur);
            } else { uses(s.rhs, cur); uses(s.lhs, cur); }
        };
        for (bool df = true; df; ) { df = false;
            for (size_t ii = n; ii-- > 0; ) { Block& b = blocks[ii];
                std::set<std::string> out;
                for (int s : b.succ) { auto it = ix.find(s); if (it != ix.end()) out.insert(lin[it->second].begin(), lin[it->second].end()); }
                std::set<std::string> cur = out;
                uses(b.cond, cur); uses(b.ret_value, cur); uses(b.ret_raw, cur); uses(b.switch_var, cur); uses(b.tail_call, cur);
                for (size_t k = b.stmts.size(); k-- > 0; ) killdef(b.stmts[k], cur);
                if (cur != lin[ii]) { lin[ii] = cur; df = true; } lout[ii] = out;
            }
        }
        /* (3) interference: at each def d, edge to every var live-AFTER, EXCEPT the copy source */
        std::map<std::string,std::set<std::string>> adj;
        auto E = [&](const std::string& a, const std::string& b){ if (a != b) { adj[a].insert(b); adj[b].insert(a); } };
        for (size_t ii = 0; ii < n; ++ii) { Block& b = blocks[ii]; size_t m = b.stmts.size();
            std::vector<std::set<std::string>> aft(m + 1); aft[m] = lout[ii];
            uses(b.cond, aft[m]); uses(b.ret_value, aft[m]); uses(b.ret_raw, aft[m]); uses(b.switch_var, aft[m]); uses(b.tail_call, aft[m]);
            for (size_t k = m; k-- > 0; ) { std::set<std::string> cur = aft[k+1]; killdef(b.stmts[k], cur); aft[k] = cur; }
            for (size_t k = 0; k < m; ++k) { Stmt& s = b.stmts[k];
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var) continue;
                const std::string& d = s.lhs->name; if (!uni.count(d)) continue;
                bool cp = s.rhs && s.rhs->kind == EK::Var; std::string src = cp ? s.rhs->name : "";
                for (auto& v : aft[k+1]) if (v != d && !(cp && v == src)) E(d, v);
            }
        }
        /* (4) union-find with conservative CLASS-vs-CLASS interference gate */
        std::map<std::string,std::string> par; std::map<std::string,std::set<std::string>> mem;
        std::function<std::string(const std::string&)> find = [&](const std::string& x) -> std::string {
            auto it = par.find(x); if (it == par.end()) { par[x] = x; return x; }
            return it->second == x ? x : par[x] = find(it->second);
        };
        for (auto& nm : uni) { find(nm); mem[nm] = {nm}; }
        auto clash = [&](const std::string& ra, const std::string& rb) -> bool {
            for (auto& a : mem[ra]) { auto it = adj.find(a); if (it == adj.end()) continue;
                for (auto& bb : mem[rb]) if (it->second.count(bb)) return true; }
            return false;
        };
        for (auto& c : cand) { std::string ra = find(c.x), rb = find(c.y);
            if (ra == rb || clash(ra, rb)) continue;
            par[rb] = ra; mem[ra].insert(mem[rb].begin(), mem[rb].end()); mem[rb].clear();
        }
        /* (5) canonical (prefer v over t, then lowest #), rename in place, drop x=x, reconcile types */
        auto better = [&](const std::string& a, const std::string& b){
            int ka = a[0]=='v'?0:1, kb = b[0]=='v'?0:1;
            return ka != kb ? ka < kb : atoi(a.c_str()+1) < atoi(b.c_str()+1);
        };
        std::map<std::string,std::string> canon;
        for (auto& nm : uni) { std::string r = find(nm), best = nm; for (auto& e : mem[r]) if (better(e, best)) best = e; canon[nm] = best; }
        for (auto& kv : canon) { const std::string& c = kv.second; const std::string& o = kv.first; if (c == o) continue;
            if (var_width.count(o)) var_width[c] = std::max(var_width.count(c) ? var_width[c] : 0, var_width[o]);
            if (var_is_float.count(o) && var_is_float[o]) var_is_float[c] = true;
            if (var_pointer.count(o) && var_pointer[o]) var_pointer[c] = true;
            if (force_float_vars.count(o)) force_float_vars.insert(c);
        }
        std::function<void(ExprP&)> ren = [&](ExprP& e){ if (!e) return;
            if (e->kind == EK::Var) { auto it = canon.find(e->name); if (it != canon.end()) e->name = it->second; }
            ren(e->a); ren(e->b); ren(e->c); for (auto& a : e->args) ren(a);
        };
        for (auto& b : blocks) { for (auto& s : b.stmts) { ren(s.lhs); ren(s.rhs); }
            ren(b.cond); ren(b.ret_value); ren(b.ret_raw); ren(b.switch_var); ren(b.tail_call); }
        for (auto& b : blocks) { std::vector<Stmt> keep;
            for (auto& s : b.stmts) {
                if (s.kind == SK::Assign && s.lhs && s.rhs && s.lhs->kind == EK::Var &&
                    s.rhs->kind == EK::Var && s.lhs->name == s.rhs->name) continue;   /* self-copy */
                keep.push_back(std::move(s));
            }
            b.stmts = std::move(keep);
        }
    }

    void global_dead_store_elim() {
        bool changed = true; int guard = 0;
        while (changed && guard++ < 16) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            size_t n = blocks.size();
            /* address-taken vars are never considered dead (value may escape) */
            std::set<std::string> addr_taken;
            for (auto& b : blocks) {
                auto scan = [&](const ExprP& e, auto&& self) -> void {
                    if (!e) return;
                    if (e->kind == EK::AddrOf && e->a && e->a->kind == EK::Var)
                        addr_taken.insert(e->a->name);
                    self(e->a, self); self(e->b, self); self(e->c, self);
                    for (auto& ar : e->args) self(ar, self);
                };
                for (auto& s : b.stmts) { scan(s.rhs, scan); scan(s.lhs, scan); }
                scan(b.cond, scan); scan(b.ret_value, scan); scan(b.ret_raw, scan);
                scan(b.switch_var, scan); scan(b.tail_call, scan);
            }

            /* per-block live-in / live-out sets over tracked var names */
            std::vector<std::set<std::string>> live_in(n), live_out(n);
            /* map block id -> index in `blocks` (ids may be sparse) */
            std::map<int,size_t> idx_of;
            for (size_t i = 0; i < n; ++i) idx_of[blocks[i].id] = i;

            bool df = true; int dg = 0;
            while (df && dg++ < 1024) {
                df = false;
                /* iterate blocks in reverse for faster convergence */
                for (size_t ii = n; ii-- > 0; ) {
                    Block& b = blocks[ii];
                    /* out = union of successors' in */
                    std::set<std::string> out;
                    for (int s : b.succ) {
                        auto it = idx_of.find(s);
                        if (it == idx_of.end()) continue;
                        out.insert(live_in[it->second].begin(),
                                   live_in[it->second].end());
                    }
                    /* transfer: in = use(terminator+stmts, backward) U (out - def) */
                    std::set<std::string> cur = out;
                    /* terminator reads happen after all stmts */
                    insert_reads(b.cond, cur);
                    insert_reads(b.ret_value, cur);
                    insert_reads(b.ret_raw, cur);
                    insert_reads(b.switch_var, cur);
                    insert_reads(b.tail_call, cur);
                    for (size_t si = b.stmts.size(); si-- > 0; ) {
                        Stmt& s = b.stmts[si];
                        /* def: plain Var assignment kills the var (write before read) */
                        if (s.kind == SK::Assign && s.lhs &&
                            s.lhs->kind == EK::Var) {
                            const std::string& dn = s.lhs->name;
                            /* live_before = (live_after - def) U uses. The def must
                             * be removed BEFORE adding the uses, so a read-modify-
                             * write `v = v OP x` keeps v live (the RHS reads it
                             * before the assignment). Erasing after inserting would
                             * wrongly kill v and drop its prior definition. */
                            cur.erase(dn);
                            insert_reads(s.rhs, cur);
                            insert_lhs_addr_reads(s.lhs, cur);
                        } else {
                            insert_reads(s.rhs, cur);
                            insert_reads(s.lhs, cur);
                        }
                    }
                    if (cur != live_in[ii]) { live_in[ii] = cur; df = true; }
                    live_out[ii] = out;
                }
            }

            /* second forward scan within each block to know liveness at the
             * point right after a given store, then drop dead stores. */
            for (size_t ii = 0; ii < n; ++ii) {
                Block& b = blocks[ii];
                size_t m = b.stmts.size();
                /* live[k] = set live immediately BEFORE stmt k; compute backward
                 * from live_out so we can test liveness after each store. */
                std::vector<std::set<std::string>> after(m + 1);
                after[m] = live_out[ii];
                /* terminator uses are part of the value live at block end */
                insert_reads(b.cond, after[m]);
                insert_reads(b.ret_value, after[m]);
                insert_reads(b.switch_var, after[m]);
                for (size_t k = m; k-- > 0; ) {
                    std::set<std::string> cur = after[k + 1];
                    Stmt& s = b.stmts[k];
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) {
                        const std::string& dn = s.lhs->name;
                        /* (live_after - def) U uses: erase def first so a
                         * read-modify-write keeps the var live (see above). */
                        cur.erase(dn);
                        insert_reads(s.rhs, cur);
                        insert_lhs_addr_reads(s.lhs, cur);
                    } else {
                        insert_reads(s.rhs, cur);
                        insert_reads(s.lhs, cur);
                    }
                    after[k] = cur;
                }
                std::vector<Stmt> keep;
                keep.reserve(m);
                for (size_t k = 0; k < m; ++k) {
                    Stmt& s = b.stmts[k];
                    bool drop = false;
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                        !has_call(s.rhs)) {
                        const std::string& dn = s.lhs->name;
                        /* only touch tracked locals/temps, never address-taken */
                        if (var_width.count(dn) && !addr_taken.count(dn) &&
                            after[k + 1].find(dn) == after[k + 1].end()) {
                            drop = true;
                        }
                    }
                    if (drop) changed = true;
                    else keep.push_back(s);
                }
                b.stmts.swap(keep);
            }
        }
    }

    /* Count total reads of a var name across the whole function. */
    int total_reads(const std::string& nm) {
        int c = 0;
        for (auto& b : blocks) {
            for (auto& s : b.stmts)
                c += count_var_reads(s.rhs, nm) + count_lhs_addr_reads(s.lhs, nm);
            /* MUST cover every expression-bearing block field or a var used only in a
             * tail-call / raw-return is under-counted -> wrongly inlined (same bug class
             * as the collect_addr_taken fix). */
            c += count_var_reads(b.cond, nm) + count_var_reads(b.ret_value, nm) +
                 count_var_reads(b.ret_raw, nm) + count_var_reads(b.switch_var, nm) +
                 count_var_reads(b.tail_call, nm);
        }
        return c;
    }

    /* A call bound to a temp that is never read is a void-style call: drop the
     * `t =` and emit it as a bare call statement (the call's side effects stay). */
    /* Drop phantom TRAILING call arguments: a bare local that is never assigned
     * anywhere and is not a parameter is reading uninitialized stack — it comes
     * from over-counting the callee's arity (a spill slot mistaken for a stack
     * arg). A genuine Nth arg is always stored by the caller first, so its slot
     * IS an assignment LHS and survives. Only trims from the END (dropping a
     * middle arg would renumber the rest). Conservative: stops at the first
     * non-phantom trailing arg. */
    void trim_phantom_call_args() {
        std::set<std::string> assigned, addr_taken;
        for (int i = 0; i < num_params; ++i) assigned.insert("a" + std::to_string(i + 1));
        /* a var whose address is taken (`&v`) may be filled by an out-parameter
         * call we don't model as an assignment — never trim such a var. */
        std::function<void(const ExprP&)> scan_addr = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::AddrOf && e->a && e->a->kind == EK::Var)
                addr_taken.insert(e->a->name);
            scan_addr(e->a); scan_addr(e->b); scan_addr(e->c);
            for (auto& ar : e->args) scan_addr(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var)
                    assigned.insert(s.lhs->name);
                scan_addr(s.lhs); scan_addr(s.rhs);
            }
            scan_addr(b.cond); scan_addr(b.ret_value); scan_addr(b.ret_raw);
            scan_addr(b.switch_var); scan_addr(b.tail_call);
        }
        auto is_phantom = [&](const ExprP& a)->bool {
            /* a never-written, never-address-taken, non-parameter bare local —
             * reading uninitialized stack. Keep ctx_* (a genuine lost incoming
             * value), array/aggregate locals (buf/sN — written through memory, not
             * scalar assignment, and legitimately passed as a pointer), and any
             * non-Var expression. */
            return a && a->kind == EK::Var &&
                   a->name.rfind("ctx_", 0) != 0 &&
                   !array_locals.count(a->name) &&
                   !assigned.count(a->name) && !addr_taken.count(a->name);
        };
        /* A REAL compiler intrinsic has a FIXED signature that MSVC knows independently of the
         * prototype we emit, so dropping an argument is a hard error, not a cosmetic choice:
         *     lock or dword ptr [rdi+0x14], eax
         *     _InterlockedOr((volatile long*)((char*)a4 + 0x14))     <- C2168, src trimmed
         * (fn_00075d88: eax's value was a phantom, so the trailing-phantom trim ate it.)
         * The OPAQUE stand-ins are the opposite -- `int32_t __pcmpeqb();` is old-style, has no
         * prototype to violate, and its arguments are documentation -- so they stay trimmable.
         * This was latent for _rotl, _byteswap and __movsb before the locked-RMW family made
         * it reachable; it is fixed for the whole class, not the one callee that hit. */
        auto fixed_arity_intrinsic = [](const std::string& c) {
            return c.rfind("_Interlocked", 0) == 0 || c.rfind("_byteswap_", 0) == 0 ||
                   c.rfind("_rotl", 0) == 0 || c.rfind("_rotr", 0) == 0 ||
                   c.rfind("__movs", 0) == 0 || c.rfind("__stos", 0) == 0 ||
                   c == "__fastfail" || c == "__rdtsc";
        };
        std::function<void(ExprP&)> visit = [&](ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Call && !fixed_arity_intrinsic(e->callee)) {
                /* trailing phantoms: safe for ANY callee — a uniform arity reduction */
                while (!e->args.empty() && is_phantom(e->args.back()))
                    e->args.pop_back();
                /* An OPAQUE intrinsic (the stand-in for an unmodeled op) is declared
                 * old-style — `int32_t __vpmovmskb();` — so it has no prototype to desync
                 * from and its arguments are documentation, not an ABI. Drop a phantom from
                 * ANY position there: an unmapped ymm/zmm operand has no value we can name,
                 * and printing a name for it would be inventing one. Trailing-only trimming
                 * left `__vpmovmskb(in_YMM1)` standing whenever a real operand followed.
                 * A REAL callee keeps its positional arguments — dropping a middle one would
                 * desync the call from its prototype (the C2197/C2198 class). */
                if (opaque_ops.count(e->callee))
                    e->args.erase(std::remove_if(e->args.begin(), e->args.end(),
                                                 [&](const ExprP& a) { return is_phantom(a); }),
                                  e->args.end());
            }
            visit(e->a); visit(e->b); visit(e->c);
            for (auto& ar : e->args) visit(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { visit(s.lhs); visit(s.rhs); }
            visit(b.cond); visit(b.ret_value); visit(b.tail_call);
        }
    }

    /* How many ARGUMENTS a printf-style format string consumes. Returns -1 when the string
     * contains no conversion at all — i.e. it is not a format string and says nothing about
     * arity. That distinction is the whole safety of the pass: `memcmp(a, "abc", 3)` has a
     * string argument too, and treating it as a format would delete the `3`.
     *
     * Handles what MSVC actually emits: %% (a literal percent, consumes nothing), flags,
     * `*` width/precision (each consumes an extra int), length modifiers, and the MSVC-only
     * I/I32/I64 sizes. Anything it cannot parse ends the scan rather than guessing. */
    static int format_arg_count(const std::string& f) {
        int n = 0; bool any = false;
        for (size_t i = 0; i + 1 < f.size(); ++i) {
            if (f[i] != '%') continue;
            if (f[i + 1] == '%') { ++i; continue; }          /* %% -> a literal '%' */
            size_t j = i + 1;
            while (j < f.size() && std::strchr("-+ #0'", f[j])) ++j;          /* flags */
            if (j < f.size() && f[j] == '*') { ++n; ++j; }                    /* width from an arg */
            else while (j < f.size() && isdigit((unsigned char)f[j])) ++j;
            if (j < f.size() && f[j] == '.') {                               /* precision */
                ++j;
                if (j < f.size() && f[j] == '*') { ++n; ++j; }
                else while (j < f.size() && isdigit((unsigned char)f[j])) ++j;
            }
            while (j < f.size() && std::strchr("hlLqjzt", f[j])) ++j;         /* length */
            if (j < f.size() && (f[j] == 'I' || f[j] == 'w')) {               /* MSVC I32/I64/w */
                ++j; while (j < f.size() && isdigit((unsigned char)f[j])) ++j;
            }
            if (j >= f.size()) break;
            if (std::strchr("diouxXeEfgGaAcspn", f[j])) { ++n; any = true; }
            else break;                       /* not a conversion we understand — stop */
            i = j;
        }
        return any ? n : -1;
    }

    /* name -> a Win32 type recovered from an API contract (HANDLE/HMODULE/DWORD/LPVOID/...).
     * Read by decl_type, so it wins over the width/pointer inference for that variable. */
    std::map<std::string, std::string> var_api_type;
    std::set<std::string> api_types_used;   /* every Win32 name emitted -> its typedef prelude */
    /* every symbolic API constant emitted -> its #define prelude. The dumped units compile
     * /TC standalone with no windows.h, so MEM_COMMIT is a C2065 unless we define it. */
    std::map<std::string,long long> api_consts_used;
    /* TEB field names emitted (name -> its byte offset) -> #define prelude. */
    std::map<std::string,long long> teb_fields_used;

    /* Callee NAME -> its function rva. The existing sig lookups all do
     * `strtoull(c.c_str() + 4, ...)`, which silently assumes every local callee is spelled
     * `fun_<hex>` -- true for a stripped binary and FALSE the moment a symbol has a real name
     * (an export, a PDB name, an RTTI-recovered method). Those callees then resolve to a
     * garbage rva and get no signature information at all. Falls back to the symbol table,
     * matching on the same sani() spelling the callee was rendered with. */
    bool callee_rva_of(const std::string& nm, uint64_t& out) {
        if (nm.rfind("fun_", 0) == 0 || nm.rfind("sub_", 0) == 0) {
            out = strtoull(nm.c_str() + 4, nullptr, 16);
            return true;
        }
        if (!e) return false;
        for (size_t i = 0; i < e->symbol_len; ++i) {
            if (!e->symbols[i].name[0]) continue;
            if (sani(std::string(e->symbols[i].name)) == nm) { out = e->symbols[i].rva; return true; }
        }
        return false;
    }

    /* WIN32 TYPES ON THE READER'S VARIABLES, not just on prototypes.
     *
     * The type library already knew `CreateFileW` returns a HANDLE and `HeapFree` takes
     * (HANDLE, DWORD, LPVOID) -- but it only ever spent that on the imported function's own
     * prototype. The LOCALS stayed anonymous, which is where a reader actually needs them:
     *     int64_t v7 = CreateFileW(...);  ...  HeapFree(v3, 0, v9);
     *     HANDLE  v7 = CreateFileW(...);  ...  HeapFree(v3, 0, v9);
     * Both directions are contracts, not guesses:
     *   RETURN  `v = CreateFileW(..)`  =>  v IS a HANDLE. The API says so.
     *   PARAM   `HeapFree(v, 0, p)`    =>  v IS a HANDLE, p IS an LPVOID, or the call would
     *                                      not compile in the original source.
     *
     * CONFLICTS ARE DROPPED, NEVER RESOLVED. If one site says a variable is a HANDLE and
     * another says DWORD, we do not know which -- one of the two inferences is wrong, and
     * picking either would be a confident lie. The variable keeps its untyped rendering.
     * Recorded in a `bad` set so a later site cannot re-type it.
     *
     * Costs nothing at the call sites: every typedef here is INTEGER-backed by design
     * (api_type_backing), so a typed local occupies the identical register slot and no
     * existing cast changes. DS_NO_APITYPES (shared with the prototype half). */
    /* CRITICAL_SECTION struct field: a field whose ADDRESS is passed to a CriticalSection API
     * IS a CRITICAL_SECTION (40 bytes on x64). The code never touches its internals -- the API
     * does -- so it does not overlap a recovered field. Turns
     *     EnterCriticalSection((char*)a1 + 8)  +  the guarded Enter..Leave region
     * into a named lock, the concurrency structure a reader actually needs.
     * Runs AFTER recover_struct_layouts -- it reads param_structs, which does not exist during
     * propagate_api_types (that runs first, on locals). DS_NO_LOCKFIELD. */
    /* The global address of `_tls_index`, or 0. Set by detect_tls_index. */
    uint64_t tls_index_addr = 0;
    /* TLS INDEX RECOVERY: find the dword global G in `__readgsqword(0x58) + G*8` -- the array
     * index the compiler uses to reach this module's thread-local storage. That global IS the
     * linker-generated `_tls_index`. One global, decidable, and it labels the whole thread-local
     * access chain. DS_NO_TLS. */
    void detect_tls_index() {
        if (std::getenv("DS_NO_TLS") || tls_index_addr) return;
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e || tls_index_addr) return;
            /* look for  <readgsqword(0x58)>  +  <G * 8>  */
            if (e->kind == EK::Binary && e->op == "+" && e->a && e->b) {
                auto is_gs58 = [](const ExprP& x) {
                    ExprP m = x; while (m && m->kind == EK::Cast && m->a) m = m->a;
                    if (!m || m->kind != EK::Call || m->callee != "__readgsqword" || m->args.empty())
                        return false;
                    ExprP arg = m->args[0];
                    /* TEB_ThreadLocalStoragePointer (0x58), whether named or raw */
                    return (arg->kind == EK::Const && arg->cval == 0x58) ||
                           (arg->kind == EK::Str && arg->text.find("ThreadLocalStorage") != std::string::npos);
                };
                ExprP gs = is_gs58(e->a) ? e->a : is_gs58(e->b) ? e->b : nullptr;
                ExprP idx = (gs == e->a) ? e->b : e->a;
                if (gs && idx && idx->kind == EK::Binary && idx->op == "*" && idx->a && idx->b) {
                    ExprP g = nullptr;
                    if (idx->b->kind == EK::Const && idx->b->cval == 8) g = idx->a;
                    else if (idx->a->kind == EK::Const && idx->a->cval == 8) g = idx->b;
                    while (g && g->kind == EK::Cast && g->a) g = g->a;
                    if (g && g->kind == EK::Mem && g->a && g->a->kind == EK::Const &&
                        (uint64_t)g->a->cval > 0x1000)
                        tls_index_addr = (uint64_t)g->a->cval;
                }
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }
    }
    void detect_lock_fields() {
        if (std::getenv("DS_NO_LOCKFIELD")) return;
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Call && !e->args.empty() &&
                (e->callee == "InitializeCriticalSection" || e->callee == "EnterCriticalSection" ||
                 e->callee == "InitializeCriticalSectionAndSpinCount")) {
                ExprP a0 = e->args[0];
                while (a0 && a0->kind == EK::Cast && a0->a) a0 = a0->a;
                std::string p; int64_t off;
                if (a0 && struct_base_offset(a0, p, off) && param_structs.count(p) &&
                    !param_structs[p].ftype.count(off))
                    param_structs[p].ftype[off] = {"CRITICAL_SECTION", 40};
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }
    }

    void propagate_api_types() {
        if (std::getenv("DS_NO_APITYPES")) return;
        std::set<std::string> bad;                 /* saw two incompatible claims -> say nothing */
        auto claim = [&](const std::string& v, const std::string& ty) {
            if (v.empty() || ty.empty() || bad.count(v)) return;
            /* NEVER OVERRIDE A PROVEN POINTER. Every typedef here is integer-backed
             * (api_type_backing) -- that is what makes a typed local free at the call sites --
             * but an integer cannot be subscripted. A variable the engine already proved is a
             * pointer, because the code DEREFERENCES it, must keep its pointer type:
             *     LPCRITICAL_SECTION j;      <- claimed from EnterCriticalSection(j)
             *     if (!(j[0x38] & 1))        <- C2109: subscript requires array or pointer
             * fn_0007f17c, caught by the cl gate. The API contract and the dereference are
             * BOTH true -- LPCRITICAL_SECTION really is a pointer -- so the honest reading is
             * that the integer-backed spelling is the wrong tool for this variable, not that
             * the dereference is wrong. Keep the type that renders correctly and say nothing.
             * Checked on the raw pointer facts, not decl_type: decl_type consults
             * var_api_type first, so it would answer with a claim already made. */
            if (array_locals.count(v)) return;
            { auto pw = ptr_elem_width.find(v);
              if (pw != ptr_elem_width.end() && pw->second > 1) return; }
            { auto vp = var_pointer.find(v);
              if (vp != var_pointer.end() && vp->second) return; }
            auto it = var_api_type.find(v);
            if (it == var_api_type.end()) { var_api_type[v] = ty; return; }
            if (it->second != ty) { var_api_type.erase(it); bad.insert(v); }
        };
        /* only a BARE variable can be claimed: `HeapFree(a1->field_8, ..)` says something
         * about a struct field, not about a local, and field typing is a separate pass. */
        auto bare = [](const ExprP& e) -> std::string {
            ExprP m = e;
            while (m && m->kind == EK::Cast && m->a) m = m->a;
            return (m && m->kind == EK::Var) ? m->name : std::string();
        };
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Call) {
                std::vector<std::string> pt;
                if (api_param_types(e->callee, pt)) {
                    for (size_t i = 0; i < pt.size() && i < e->args.size(); ++i) {
                        if (pt[i] != "int") claim(bare(e->args[i]), pt[i]);
                        /* WIDE STRING LITERALS. The type library says this parameter is a
                         * LPCWSTR, so a constant address in it addresses a UTF-16 literal --
                         * a decidable fact from the API contract, not a guess about the
                         * bytes. read_cstring cannot find these (it sees 'V' then a NUL), so
                         * every wide literal in the binary was a bare number:
                         *     GetModuleHandleW(0x87718)
                         *     GetModuleHandleW(L"VALORANT-Win64-Shipping.exe")
                         * Only for the W-typed params; an LPCSTR arg is already handled by
                         * the byte-wise reader. */
                        if ((pt[i] == "LPCWSTR" || pt[i] == "LPWSTR") &&
                            e->args[i] && e->args[i]->kind == EK::Const &&
                            !e->args[i]->is_float && e->args[i]->cval > 0) {
                            std::string ws;
                            uint64_t a = (uint64_t)e->args[i]->cval;
                            uint64_t r = (this->e && a >= this->e->base) ? a - this->e->base : a;
                            if (read_wstring(r, ws)) e->args[i] = mkText("L\"" + ws + "\"", 8);
                        }
                        /* SYMBOLIC CONSTANTS. The API's contract fixes what this parameter's
                         * bits mean, so a magic number in it is decidably nameable:
                         *   VirtualAlloc(v10, 0x1000, 0x3000, 0x40)
                         *   VirtualAlloc(v10, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
                         * api_const_str declines unless it can name the value EXACTLY (every
                         * flag bit covered), so a partial match never renders a half-truth. */
                        if (e->args[i] && e->args[i]->kind == EK::Const && !e->args[i]->is_float) {
                            std::string cs = api_const_str(e->callee, (int)i,
                                                           (long long)e->args[i]->cval,
                                                           api_consts_used);
                            if (!cs.empty()) e->args[i] = mkText(cs, e->args[i]->width);
                        }
                    }
                }
            }
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                /* `v = <api>(...)` : the API's return type IS v's type */
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && s.rhs) {
                    ExprP r = s.rhs;
                    while (r && r->kind == EK::Cast && r->a) r = r->a;
                    if (r && r->kind == EK::Call) {
                        claim(s.lhs->name, api_ret_type(r->callee));
                        /* ... and through a LOCAL wrapper: `HMODULE dll = GetDllBase();`.
                         * build_sig_table propagated the API's return type across the call
                         * graph, so the caller gets it without ever seeing the import. */
                        uint64_t crva = 0;
                        if (sigtab && callee_rva_of(r->callee, crva)) {
                            auto si = sigtab->find(crva);
                            if (si != sigtab->end()) claim(s.lhs->name, si->second.ret_api);
                        }
                    }
                }
                scan(s.lhs); scan(s.rhs);
            }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw);
            scan(b.switch_var); scan(b.tail_call);
        }
        for (const std::string& v : bad) var_api_type.erase(v);
        for (auto& kv : var_api_type) api_types_used.insert(kv.second);
    }

    /* THE FORMAT STRING IS A DECIDABLE ORACLE FOR A VARIADIC CALL'S REAL ARITY.
     *
     * A variadic callee has no prototype to read an argument count from, so the engine falls
     * back to the x64 ABI and assumes all four integer arg registers are live. Whatever
     * happened to be in the leftovers gets printed as an argument. Measured, verbatim:
     *     fun_00001310("[NullWare] Game module found at 0x%p\n", v2, 4, 0)
     *     fun_00001310("[NullWare] Game base: 0x%llX\n", qword_173fb0, s1, 0x18)
     * One %p, three arguments. `4, 0` and `s1, 0x18` are register RESIDUE from a nearby call
     * — they are not arguments, they were never passed, and they read as though the program
     * does something it does not. The callee is genuinely variadic: its prologue is the
     * textbook MSVC va_start (rcx/rdx/r8/r9 all homed to shadow space before the frame, then
     * `lea rdi, [rsp+0x58]` = the va_arg area).
     *
     * The format string states exactly how many arguments the SOURCE passed, so the residue
     * is decidably removable. Only ever TRIMS: it never invents an argument it cannot see,
     * and a call already at or below the stated arity is untouched.
     *
     * Safe against the prototype-desync class (C2197/C2198) because a callee reached this way
     * is emitted old-style — `int32_t fun_00001310();` — which accepts any arity. It does not
     * touch known_api callees, whose argc comes from the type library and is authoritative.
     * DS_NO_FMTARITY. */
    void trim_format_args() {
        if (std::getenv("DS_NO_FMTARITY")) return;
        std::function<void(ExprP&)> visit = [&](ExprP& e) {
            if (!e) return;
            int _ac = 0, _rk = 0;
            if (e->kind == EK::Call && e->args.size() > 1 &&
                !known_api(e->callee, _ac, _rk)) {
                /* Is the callee a PROVEN variadic (build_sig_table saw the va_start home-spill)?
                 * That upgrades the format string from "at least this many" to EXACTLY this
                 * many, which is the only way to trim a call whose format has NO conversions:
                 *     fun_00001310("[NullWare] Waiting for VALORANT...\n", 0, 4, 0)
                 * has zero %-specs, so nc == 0 says nothing on its own -- a plain
                 * `memcmp(a, "abc", 3)` looks identical. Proven-variadic is what separates them. */
                bool vararg_callee = false;
                uint64_t vcrva = 0;
                if (sigtab && callee_rva_of(e->callee, vcrva)) {
                    auto si = sigtab->find(vcrva);
                    if (si != sigtab->end()) vararg_callee = si->second.is_variadic;
                }
                for (size_t i = 0; i + 1 < e->args.size(); ++i) {
                    const ExprP& a = e->args[i];
                    if (!a || a->kind != EK::Str) continue;
                    int nc = format_arg_count(a->text);
                    if (nc < 0) {                         /* no conversions at all */
                        if (!vararg_callee) continue;     /* says nothing -- could be memcmp */
                        nc = 0;                           /* proven variadic: exactly the format */
                    }
                    size_t want = i + 1 + (size_t)nc;
                    if (e->args.size() > want) e->args.resize(want);
                    break;                                /* the first format string wins */
                }
            }
            visit(e->a); visit(e->b); visit(e->c);
            for (auto& ar : e->args) visit(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { visit(s.lhs); visit(s.rhs); }
            visit(b.cond); visit(b.ret_value); visit(b.ret_raw);
            visit(b.switch_var); visit(b.tail_call);
        }
    }

    void simplify_unused_call_temps() {
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                    call_temps.count(s.lhs->name) && s.rhs && has_call(s.rhs) &&
                    total_reads(s.lhs->name) == 0) {
                    s.kind = SK::Call;
                    s.lhs = nullptr;
                }
            }
        }
    }
    int total_writes(const std::string& nm) {
        int c = 0;
        for (auto& b : blocks)
            for (auto& s : b.stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                    s.lhs->name == nm) c++;
        return c;
    }

    /* Inline a single-def, single-use temp into its one use when both live in the
     * same block with no intervening hazard. Folds `v3 = t4; t3 = v3 + t5;` to
     * `t3 = t4 + t5;`. Conservative: only for tN/vN temps written exactly once
     * and read exactly once, with a side-effect-free rhs. */
    void walk_addr_taken(const ExprP& e, std::set<std::string>& out) {
        if (!e) return;
        if (e->kind == EK::AddrOf && e->a && e->a->kind == EK::Var)
            out.insert(e->a->name);
        walk_addr_taken(e->a, out);
        walk_addr_taken(e->b, out);
        walk_addr_taken(e->c, out);
        for (auto& ar : e->args) walk_addr_taken(ar, out);
    }
    void collect_addr_taken(std::set<std::string>& out) {
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { walk_addr_taken(s.lhs, out); walk_addr_taken(s.rhs, out); }
            /* MUST scan every expression-carrying block field, not just cond: a
             * bit-reinterpret `*(u64*)&t` (movd/movq float->GP) or an out-param `&v`
             * often lives in the RETURN value / tail-call args / switch selector. If
             * missed here, a consumer (copy_propagate, coalesce, the temp inliners)
             * treats the var as non-address-taken and inlines its def into the `&`,
             * emitting `&(cast)` / `&(a+b)` — a non-lvalue (C2102). */
            walk_addr_taken(b.cond, out);
            walk_addr_taken(b.ret_value, out);
            walk_addr_taken(b.ret_raw, out);
            walk_addr_taken(b.switch_var, out);
            walk_addr_taken(b.tail_call, out);
        }
    }

    void copy_propagate() {
        /* A variable whose address is taken (`&v` / passed by-ref as an out-param)
         * can be mutated through that pointer, so its definition must NEVER be
         * inlined into a use — doing so both loses the callee's write-back and
         * folds nonsense like `&v1` into `&*(int*)(...)`. */
        std::set<std::string> addr_taken;
        collect_addr_taken(addr_taken);
        bool changed = true; int guard = 0;
        while (changed && guard++ < 8) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            /* Snapshot whole-function read/write counts ONCE per iteration instead of
             * calling total_reads/total_writes (each a full-function scan) per def —
             * that was O(defs * function_size) = O(n^2) and dominated big functions.
             * Inlining a single-read/single-write copy relocates the inlined subtree's
             * leaves but preserves every OTHER var's read/write count, so this snapshot
             * stays exact for every def considered in the pass; the outer `while`
             * re-snapshots to expose chains a prior inline created. The `!= 1` tests are
             * identical to the per-def scans, so the output is byte-for-byte unchanged. */
            std::map<std::string,int> reads_map, writes_map;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) {
                    tally_reads(s.rhs, reads_map);
                    if (s.lhs && s.lhs->kind == EK::Mem) tally_reads(s.lhs->a, reads_map);
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var)
                        writes_map[s.lhs->name]++;
                }
                tally_reads(b.cond, reads_map);
                tally_reads(b.ret_value, reads_map);
                tally_reads(b.ret_raw, reads_map);
                tally_reads(b.switch_var, reads_map);
                tally_reads(b.tail_call, reads_map);
            }
            for (auto& b : blocks) {
                /* iterate to the LAST stmt (not size-1): a `result = e` that is the
                 * final stmt has its only use in the TERMINATOR (ret_value/cond/switch/
                 * tail_call), so it must be considered for terminal-inline too. The
                 * stmt-use search below simply finds nothing and falls to that path. */
                for (size_t i = 0; i < b.stmts.size(); ++i) {
                    Stmt& def = b.stmts[i];
                    if (def.kind != SK::Assign || !def.lhs || def.lhs->kind != EK::Var)
                        continue;
                    const std::string nm = def.lhs->name;
                    /* params and stack arrays are never inlined away */
                    if (nm.size()==2 && nm[0]=='a' && nm[1]>='1' && nm[1]<='4') continue;
                    if (array_locals.count(nm)) continue;
                    if (addr_taken.count(nm)) continue;
                    if (writes_map[nm] != 1) continue;
                    if (reads_map[nm] != 1) continue;
                    /* AGGRESSIVE (DS_NO_CALLINLINE disables): a CALL-result temp used
                     * exactly once IS inlined into its use (`t=f(); v=t+1` -> `v=f()+1`)
                     * — the dominant temp-cascade source and the biggest gap vs Hex-Rays.
                     * A call has side effects + may read/write through pointers, so it is
                     * only safe to move to the use site when NOTHING between the def and
                     * the use has a call or touches memory (read OR write), and the use
                     * itself has no OTHER call (evaluation order of two calls in one
                     * expression is unspecified). These extra hazards are applied below
                     * when rhs_has_call. */
                    /* only an IMPURE call needs reorder hazards — a pure `__`-intrinsic
                     * (__mulh/__fabs/__bsr) is a side-effect-free value like any expr. */
                    bool rhs_has_call = has_impure_call(def.rhs);
                    if (rhs_has_call && std::getenv("DS_NO_CALLINLINE")) continue;
                    /* find the single use in this block after i */
                    int use = -1;
                    for (size_t j = i + 1; j < b.stmts.size(); ++j) {
                        if (count_var_reads(b.stmts[j].rhs, nm) +
                            count_lhs_addr_reads(b.stmts[j].lhs, nm) > 0) { use = (int)j; break; }
                    }
                    if (use < 0) {
                        /* The single use is the BRANCH CONDITION (`t = *p & m; if (t)`),
                         * the RETURN VALUE (`t = e; return t;`), or the SWITCH SELECTOR,
                         * not a statement. Inline it there so the block becomes
                         * statement-free — which lets merge_short_circuit fold the
                         * `&&`/`||` chain into one predicate (the dominant goto source:
                         * every compiler `a && b || c` is a chain of compare blocks) and
                         * collapses `t=e; return t;` -> `return e;`. Same hazard rules;
                         * these are evaluated after all stmts, so the window is def+1..end. */
                        /* the terminal use is the branch cond, the RETURN value/raw,
                         * the SWITCH selector, or a TAIL-CALL arg. Covering all of them
                         * (the comment above always claimed to, but only `cond` was wired)
                         * collapses `t = e; return t;` -> `return e;` and the switch/tail
                         * equivalents — the Hex-Rays single-`result` return shape. */
                        ExprP* tgt = nullptr;
                        if (b.cond && count_var_reads(b.cond, nm) > 0) tgt = &b.cond;
                        else if (b.ret_value && count_var_reads(b.ret_value, nm) > 0) tgt = &b.ret_value;
                        else if (b.ret_raw && count_var_reads(b.ret_raw, nm) > 0) tgt = &b.ret_raw;
                        else if (b.switch_var && count_var_reads(b.switch_var, nm) > 0) tgt = &b.switch_var;
                        else if (b.tail_call && count_var_reads(b.tail_call, nm) > 0) tgt = &b.tail_call;
                        if (tgt) {
                            /* a call inlined into a condition that ALREADY has an impure
                             * call is safe ONLY if the cond has exactly ONE impure call
                             * and t1 nests inside its args (`g(f())` — f before g); any
                             * sibling reorders. */
                            if (rhs_has_call && has_impure_call(*tgt) &&
                                (count_impure_calls(*tgt) != 1 ||
                                 reads_var_outside_call_args(*tgt, nm))) continue;
                            bool rhs_mem2 = reads_mem(def.rhs);
                            bool hz = false;
                            for (int j = (int)i + 1; j < (int)b.stmts.size(); ++j) {
                                Stmt& s = b.stmts[j];
                                if (s.kind == SK::Comment) continue;
                                if (s.kind != SK::Assign) { hz = true; break; }
                                if (has_call(s.rhs)) { hz = true; break; }
                                if (s.lhs && s.lhs->kind == EK::Mem && (rhs_mem2 || rhs_has_call)) { hz = true; break; }
                                /* a call may read memory a later store hasn't yet made, or
                                 * write memory a later read would see stale — so ANY
                                 * intervening memory touch reorders it. */
                                if (rhs_has_call && reads_mem(s.rhs)) { hz = true; break; }
                                if (s.lhs && s.lhs->kind == EK::Var &&
                                    reads_named_var(def.rhs, s.lhs->name)) { hz = true; break; }
                            }
                            if (!hz) {
                                subst_var(*tgt, nm, def.rhs);
                                *tgt = fold(*tgt);
                                def.kind = SK::Comment; def.label = "";
                                b.stmts.erase(b.stmts.begin() + i);
                                changed = true;
                                break;
                            }
                        }
                        continue;     /* used in another block / hazard: skip */
                    }
                    /* a call inlined into a use with another impure call is safe ONLY
                     * when the ENTIRE use (store address lhs + value rhs — their eval
                     * order is unspecified) has EXACTLY ONE impure call and t1 NESTS
                     * inside its args (`g(f())` — f evaluates before g); a sibling
                     * (`f()+g()`, `*(f()+8)=g()`) has unspecified order. This captures
                     * the dominant chained-call cascade `t=get(); use(t)`. */
                    if (rhs_has_call) {
                        int use_calls = count_impure_calls(b.stmts[use].rhs) +
                                        count_impure_calls(b.stmts[use].lhs);
                        bool outside = reads_var_outside_call_args(b.stmts[use].rhs, nm) ||
                                       reads_var_outside_call_args(b.stmts[use].lhs, nm);
                        if (use_calls > 0 && (use_calls != 1 || outside)) continue;
                    }
                    /* hazard check: rhs must not read a var/mem rewritten between */
                    bool rhs_mem = reads_mem(def.rhs);
                    bool hazard = false;
                    for (int j = (int)i + 1; j < use; ++j) {
                        Stmt& s = b.stmts[j];
                        if (s.kind != SK::Assign) { hazard = true; break; }
                        if (has_call(s.rhs)) { hazard = true; break; }
                        if (s.lhs && s.lhs->kind == EK::Mem && (rhs_mem || rhs_has_call)) { hazard = true; break; }
                        if (rhs_has_call && reads_mem(s.rhs)) { hazard = true; break; }
                        if (s.lhs && s.lhs->kind == EK::Var &&
                            reads_named_var(def.rhs, s.lhs->name)) { hazard = true; break; }
                    }
                    if (hazard) continue;
                    /* the use statement must not itself write nm before reading */
                    /* perform substitution */
                    ExprP val = def.rhs;
                    subst_var(b.stmts[use].rhs, nm, val);
                    subst_var(b.stmts[use].lhs, nm, val);
                    /* re-fold the use site: inlining can expose new constant folds
                     * (e.g. `t=field_0*9; ... t*8` -> `field_0*72`) that fold() never
                     * saw because the two multiplies lived in separate statements. */
                    b.stmts[use].rhs = fold(b.stmts[use].rhs);
                    if (b.stmts[use].lhs && b.stmts[use].lhs->kind == EK::Mem)
                        b.stmts[use].lhs = fold(b.stmts[use].lhs);
                    def.kind = SK::Comment; def.label = "";  /* mark removed */
                    /* remove the now-empty comment slot */
                    b.stmts.erase(b.stmts.begin() + i);
                    changed = true;
                    break;   /* indices shifted; restart this block */
                }
            }
        }
    }

    /* Hex-Rays `return X;` shape. Fold `v = e; return v;` -> `return e;` where v is the
     * return variable, single-def, used ONLY in this block's ret_value/ret_raw. This is
     * exactly the case copy_propagate cannot reach: the return value is cloned into BOTH
     * ret_value AND ret_raw (a typing mirror), so total_reads==2 fails its single-use
     * gate — yet ret_text emits ret_value ONLY (ret_raw is analysis-only, never emitted),
     * so folding e into ret_value is a SINGLE evaluation even when e is a call. The same
     * reorder hazards as copy_propagate guard a non-terminal def. Gated DS_NO_RETFOLD. */
    void fold_return_temps() {
        if (std::getenv("DS_NO_RETFOLD")) return;
        std::set<std::string> addr; collect_addr_taken(addr);
        for (auto& b : blocks) {
            if (b.stmts.empty() || !b.ret_value) continue;
            /* D2/D3: fold ANY single-use in-block temp read EXACTLY ONCE in the return, so
             * `v = f(...); return (signed char)(v != 0);` -> `return (signed char)(f(...) != 0);`
             * (not just the bare-leaf `return v;` the old code handled). All the soundness gates
             * are preserved; two extra guards keep it correct for call temps. */
            for (int di = 0; di < (int)b.stmts.size(); ++di) {
                Stmt& def = b.stmts[di];
                if (def.kind != SK::Assign || !def.lhs || def.lhs->kind != EK::Var || !def.rhs) continue;
                const std::string v = def.lhs->name;
                if (addr.count(v) || array_locals.count(v)) continue;
                if (v.size()==2 && v[0]=='a' && v[1]>='1' && v[1]<='4') continue;   /* never a param */
                if (total_writes(v) != 1) continue;
                int here = count_var_reads(b.ret_value, v) + count_var_reads(b.ret_raw, v);
                if (total_reads(v) != here) continue;             /* used ONLY in the return */
                if (count_var_reads(b.ret_value, v) != 1) continue;   /* (a) never duplicate a call */
                bool used_before = false;                          /* no earlier stmt reads v (else it's a real use) */
                for (int i = 0; i < di; ++i)
                    if (count_var_reads(b.stmts[i].rhs, v) + count_lhs_addr_reads(b.stmts[i].lhs, v)) { used_before = true; break; }
                if (used_before) continue;
                /* reorder hazard for stmts after the def (the return evaluates after all stmts) */
                bool rmem = reads_mem(def.rhs), rcall = has_impure_call(def.rhs); bool hz = false;
                for (int j = di + 1; j < (int)b.stmts.size() && !hz; ++j) {
                    Stmt& s = b.stmts[j];
                    if (s.kind != SK::Assign) { hz = true; break; }
                    if ((rmem || rcall) && (has_call(s.rhs) || (s.lhs && s.lhs->kind == EK::Mem))) hz = true;
                    else if (rcall && reads_mem(s.rhs)) hz = true;
                    else if (s.lhs && s.lhs->kind == EK::Var && reads_named_var(def.rhs, s.lhs->name)) hz = true;
                }
                if (hz) continue;
                /* (b) chained-call guard: if the def is an impure call, the return may hold at most
                 * ONE impure call and v must NEST in its args (so f() evaluates before it) — a sibling
                 * call (`f() + g()`) has unspecified order and must not be reordered. */
                if (rcall) {
                    int rc = count_impure_calls(b.ret_value);
                    if (rc > 0 && (rc != 1 || reads_var_outside_call_args(b.ret_value, v))) continue;
                }
                subst_var(b.ret_value, v, def.rhs); b.ret_value = fold(b.ret_value);
                b.ret_raw = clone(b.ret_value);   /* mirror kept consistent; never emitted */
                b.stmts.erase(b.stmts.begin() + di);
                break;                            /* erase invalidates di; one return per block */
            }
        }
    }

    /* Inline a temp whose def is DEAD after its block and whose single use is in that
     * same block after the def. Because the temp is not read in any block reachable
     * from here, its value can't escape — safe even when the temp is a REUSED
     * (multi-def) stack slot that inline_local_loads / fold_return_temps refuse (both
     * gate on single-def). Cleans the common zero-init-and-store shape
     * `v = 0; *(a1) = v; return a1;`  ->  `*(a1) = 0; return a1;` (the store block
     * jumps to a shared return epilogue, so it doesn't literally `ends_ret`; the
     * dead-after analysis catches it). Gated DS_NO_TERMFOLD. */
    void fold_dead_block_temps() {
        if (std::getenv("DS_NO_TERMFOLD")) return;
        if (blocks.size() > 300) return;                 /* keep the O(N*E) closure bounded (big fns = low yield) */
        bool DBG = std::getenv("DS_DBG_TERMFOLD") && f;
        std::set<std::string> addr; collect_addr_taken(addr);
        auto is_tmp = [&](const std::string& n){
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) return false;
            for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') return false;
            return !array_locals.count(n);
        };
        /* node_reads[i] = var names READ in block i (Mem-lhs contributes its address,
         * a plain Var lhs is a WRITE not a read). */
        std::vector<std::set<std::string>> node_reads(blocks.size());
        for (size_t i = 0; i < blocks.size(); ++i) {
            std::function<void(const ExprP&)> cv = [&](const ExprP& e){
                if (!e) return; if (e->kind == EK::Var) node_reads[i].insert(e->name);
                cv(e->a); cv(e->b); cv(e->c); for (auto& a : e->args) cv(a); };
            Block& bl = blocks[i];
            for (auto& s : bl.stmts) { cv(s.rhs); if (s.lhs && s.lhs->kind == EK::Mem) cv(s.lhs); }
            cv(bl.cond); cv(bl.ret_value); cv(bl.ret_raw); cv(bl.switch_var); cv(bl.tail_call);
        }
        auto succs = [&](int i, std::vector<int>& out){
            Block& bl = blocks[i];
            if (bl.taken >= 0) out.push_back(bl.taken);
            if (bl.fall >= 0) out.push_back(bl.fall);
            if (bl.default_succ >= 0) out.push_back(bl.default_succ);
            for (int c : bl.case_succ) if (c >= 0) out.push_back(c);
        };
        /* reach_reads[i] = var names read in any block transitively reachable from i's
         * successors (NOT including i itself). Fixpoint over the succ graph. */
        std::vector<std::set<std::string>> reach_reads(blocks.size());
        bool ch = true; int gg = 0;
        while (ch && gg++ < (int)blocks.size() + 4) {
            ch = false;
            for (size_t i = 0; i < blocks.size(); ++i) {
                std::vector<int> sc; succs((int)i, sc);
                size_t before = reach_reads[i].size();
                for (int s : sc) if (s >= 0 && s < (int)blocks.size()) {
                    reach_reads[i].insert(node_reads[s].begin(), node_reads[s].end());
                    reach_reads[i].insert(reach_reads[s].begin(), reach_reads[s].end());
                }
                if (reach_reads[i].size() != before) ch = true;
            }
        }
        for (size_t bidx = 0; bidx < blocks.size(); ++bidx) {
            Block& b = blocks[bidx];
            bool changed = true; int guard = 0;
            while (changed && guard++ < 400) {
                if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
                changed = false;
                for (int di = 0; di < (int)b.stmts.size(); ++di) {
                    Stmt& def = b.stmts[di];
                    if (def.kind != SK::Assign || !def.lhs || def.lhs->kind != EK::Var || !def.rhs) continue;
                    const std::string v = def.lhs->name;
                    if (!is_tmp(v)) { continue; }
                    if (addr.count(v)) { if(DBG) fprintf(stderr,"[TF] skip %s addr-taken\n",v.c_str()); continue; }
                    if (reach_reads[bidx].count(v)) { if(DBG) fprintf(stderr,"[TF] skip %s live-after blk%zu (succ reads it)\n",v.c_str(),bidx); continue; }
                    if (has_impure_call(def.rhs) || node_count(def.rhs) > 16) { if(DBG) fprintf(stderr,"[TF] skip %s call/big\n",v.c_str()); continue; }
                    /* next redef of v after di (bounds the def's live range in-block) */
                    int nextw = (int)b.stmts.size();
                    for (int j = di + 1; j < (int)b.stmts.size(); ++j)
                        if (b.stmts[j].kind == SK::Assign && b.stmts[j].lhs &&
                            b.stmts[j].lhs->kind == EK::Var && b.stmts[j].lhs->name == v) { nextw = j; break; }
                    /* reads of v in (di, nextw): stmt uses + (if no redef before end) terminal fields */
                    std::vector<int> rd;
                    for (int j = di + 1; j < nextw; ++j)
                        if (count_var_reads(b.stmts[j].rhs, v) + count_lhs_addr_reads(b.stmts[j].lhs, v)) rd.push_back(j);
                    bool termread = (nextw == (int)b.stmts.size()) &&
                        (count_var_reads(b.cond, v) + count_var_reads(b.ret_value, v) + count_var_reads(b.ret_raw, v)
                         + count_var_reads(b.switch_var, v) + count_var_reads(b.tail_call, v)) > 0;
                    if ((int)rd.size() + (termread ? 1 : 0) != 1) { if(DBG) fprintf(stderr,"[TF] skip %s nuses=%d\n",v.c_str(),(int)rd.size()+(termread?1:0)); continue; }   /* exactly one use of THIS def */
                    int usepos = rd.empty() ? (int)b.stmts.size() : rd[0];
                    /* input stability + reorder hazard between def and use */
                    std::set<std::string> ins;
                    std::function<void(const ExprP&)> col = [&](const ExprP& e){
                        if (!e) return; if (e->kind == EK::Var) ins.insert(e->name);
                        col(e->a); col(e->b); col(e->c); for (auto& a : e->args) col(a); };
                    col(def.rhs);
                    bool rmem = reads_mem(def.rhs); bool hz = false;
                    for (int j = di + 1; j < usepos && !hz; ++j) {
                        Stmt& s = b.stmts[j];
                        if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && ins.count(s.lhs->name)) hz = true;
                        else if (rmem && has_call(s.rhs)) hz = true;
                        else if (rmem && s.lhs && s.lhs->kind == EK::Mem) hz = true;
                    }
                    if (hz) continue;
                    ExprP val = def.rhs;
                    if (usepos < (int)b.stmts.size()) {
                        subst_var(b.stmts[usepos].rhs, v, val); subst_var(b.stmts[usepos].lhs, v, val);
                    } else {
                        subst_var(b.cond, v, val); subst_var(b.ret_value, v, val); subst_var(b.ret_raw, v, val);
                        subst_var(b.switch_var, v, val); subst_var(b.tail_call, v, val);
                    }
                    b.stmts.erase(b.stmts.begin() + di);
                    changed = true; break;
                }
            }
        }
    }

    void subst_var(ExprP& e, const std::string& nm, const ExprP& val) {
        if (!e) return;
        /* Replace the expression ITSELF when it is the target variable. The old
         * code only checked e->a/b/c, so a use where the variable is the whole
         * expression (e.g. `*p = v4;` — rhs is bare `v4`) was never substituted,
         * yet copy_propagate still deleted the definition, leaving a dangling
         * reference. This corrupts every load-then-store / swap pattern. */
        if (e->kind == EK::Var && e->name == nm) { e = clone(val); return; }
        subst_var(e->a, nm, val);
        subst_var(e->b, nm, val);
        subst_var(e->c, nm, val);
        for (auto& ar : e->args) subst_var(ar, nm, val);
    }

    /* AGGRESSIVE TEMP REDUCER (DS_NO_INVINLINE). Inline every single-DEF, non-address-
     * taken temp whose rhs is a SMALL, side-effect-free, MEMORY-FREE expression built
     * only from single-def / param inputs — an SSA/loop-invariant value that is safe to
     * RECOMPUTE at each use. This is what makes Hex-Rays render `(char*)a1 + 0x10` /
     * `v3 * 8` / `(int)v5` inline instead of parking them in a tN, collapsing the
     * residual temp cloud that copy_propagate (single-use) and coalesce (copies) leave.
     * SOUND: a single-def var never changes after its def, and memory-free means no
     * aliasing store can invalidate the value, so recomputing it anywhere is identical.
     * Iterates so a chain (t2 feeds t1) fully collapses. */
    void inline_invariant_temps() {
        if (std::getenv("DS_NO_INVINLINE")) return;
        std::set<std::string> addr; collect_addr_taken(addr);
        auto is_tmp = [&](const std::string& n){
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) return false;
            for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') return false;
            return !array_locals.count(n);
        };
        bool changed = true; int guard = 0;
        while (changed && guard++ < 15) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            std::map<std::string,int> writes;
            for (auto& b : blocks) for (auto& s : b.stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) writes[s.lhs->name]++;
            for (auto& b : blocks) {
                for (auto& def : b.stmts) {
                    if (def.kind != SK::Assign || !def.lhs || def.lhs->kind != EK::Var || !def.rhs) continue;
                    const std::string nm = def.lhs->name;
                    if (!is_tmp(nm) || addr.count(nm) || writes[nm] != 1) continue;
                    if (has_call(def.rhs) || reads_mem(def.rhs) || node_count(def.rhs) > 8) continue;
                    /* TRULY invariant only: every var input must be a PARAM (aN) — a param
                     * never changes, so the expr is the same at every program point on EVERY
                     * path/iteration. A single-static-def LOCAL is NOT enough: it may be
                     * loop-carried (`v=v+1`) or reloaded per iteration (`v=a[i]`), giving a
                     * different value each time — inlining it globally would be UNSOUND. */
                    bool inv = true;
                    std::function<void(const ExprP&)> chk = [&](const ExprP& e){
                        if (!e || !inv) return;
                        if (e->kind == EK::Var) {
                            bool is_param = e->name.size() >= 2 && e->name[0] == 'a' &&
                                            e->name[1] >= '1' && e->name[1] <= '9';
                            auto w = writes.find(e->name);
                            bool reassigned = w != writes.end() && w->second > 0;
                            /* a param is invariant ONLY if it is NEVER reassigned — a
                             * clamp/saturate `a1 = lo;` makes `(char*)a1+K` iteration-
                             * and path-dependent, so a global recompute would be wrong. */
                            if (!is_param || reassigned || addr.count(e->name)) inv = false;
                        }
                        chk(e->a); chk(e->b); chk(e->c); for (auto& a : e->args) chk(a);
                    };
                    chk(def.rhs);
                    if (!inv) continue;
                    /* PROVABLY-SOUND GUARD: the def must DOMINATE every use. `writes[nm]`
                     * counts only explicit SK::Assign stmts, but a param-HOME alias local
                     * gets its initial value implicitly (`int v2 = a2;` is v2 sharing a2's
                     * home slot, NOT an assign), so a swap `v2 = a3;` inside a branch is the
                     * ONLY counted def -> writes[v2]==1 misidentifies v2 as single-def. A
                     * genuine single-def invariant temp's def dominates all its uses; a
                     * misidentified one (branch def, used after the join) does NOT dominate
                     * the join use. Requiring dominance refuses exactly the unsound case and
                     * costs nothing on real invariants (defined once, early). */
                    int def_blk = b.id;
                    bool dom_ok = true;
                    for (auto& b2 : blocks) {
                        if (!dom_ok) break;
                        bool uses = false;
                        for (auto& s2 : b2.stmts) { if (&s2 == &def) continue;
                            if (count_var_reads(s2.rhs, nm) + count_lhs_addr_reads(s2.lhs, nm)) { uses = true; break; } }
                        if (!uses) uses = count_var_reads(b2.cond, nm) || count_var_reads(b2.ret_value, nm) ||
                                          count_var_reads(b2.ret_raw, nm) || count_var_reads(b2.switch_var, nm) ||
                                          count_var_reads(b2.tail_call, nm);
                        if (uses && !dominates(def_blk, b2.id)) dom_ok = false;
                    }
                    if (!dom_ok) continue;
                    ExprP val = def.rhs;
                    for (auto& b2 : blocks) {
                        for (auto& s2 : b2.stmts) { if (&s2 == &def) continue; subst_var(s2.rhs, nm, val); subst_var(s2.lhs, nm, val); }
                        subst_var(b2.cond, nm, val); subst_var(b2.ret_value, nm, val); subst_var(b2.ret_raw, nm, val);
                        subst_var(b2.switch_var, nm, val); subst_var(b2.tail_call, nm, val);
                    }
                    def.kind = SK::Comment; def.label = "\x01inl";   /* mark removed */
                    changed = true;
                }
            }
            if (changed) for (auto& b : blocks)
                b.stmts.erase(std::remove_if(b.stmts.begin(), b.stmts.end(),
                    [](const Stmt& s){ return s.kind == SK::Comment && s.label == "\x01inl"; }), b.stmts.end());
        }
    }

    /* SAME-BLOCK MEMORY-LOAD INLINER (DS_NO_LOADINLINE). The bulk of the residual temps
     * are field/array LOADS (`t = a1->field_8`). Inlining a load requires that neither
     * its ADDRESS (its var inputs) nor the MEMORY it reads changes between the def and
     * each use. This handles the common case SOUNDLY: a single-def load whose EVERY use
     * is in the def's own block, with NO store and NO call between the def and the last
     * use (either would alias/clobber the loaded cell). The address' var inputs must be
     * single-def/param (invariant) so the address itself is stable. */
    void inline_local_loads() {
        if (std::getenv("DS_NO_LOADINLINE")) return;
        std::set<std::string> addr; collect_addr_taken(addr);
        auto is_tmp = [&](const std::string& n){
            if (n.size() < 2 || (n[0] != 'v' && n[0] != 't')) return false;
            for (size_t i = 1; i < n.size(); ++i) if (n[i] < '0' || n[i] > '9') return false;
            return !array_locals.count(n);
        };
        bool changed = true; int guard = 0;
        while (changed && guard++ < 12) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            std::map<std::string,int> writes;
            for (auto& b : blocks) for (auto& s : b.stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) writes[s.lhs->name]++;
            for (size_t bi = 0; bi < blocks.size(); ++bi) {
                Block& b = blocks[bi];
                for (size_t i = 0; i < b.stmts.size(); ++i) {
                    Stmt& def = b.stmts[i];
                    if (def.kind != SK::Assign || !def.lhs || def.lhs->kind != EK::Var || !def.rhs) continue;
                    const std::string nm = def.lhs->name;
                    if (!is_tmp(nm) || addr.count(nm) || writes[nm] != 1) continue;
                    if (has_call(def.rhs) || node_count(def.rhs) > 14) continue;
                    bool rmem = reads_mem(def.rhs);
                    /* within ONE block execution a single-def input never changes (no
                     * reassignment, and a loop re-entry crosses a block boundary), so a
                     * same-block memory-free expr OR a memory load with no aliasing store
                     * between def and use is safe to inline. The ADDRESS/inputs must be
                     * single-def/param so they are stable; memory loads additionally need
                     * the store/call barrier check below. */
                    bool stable = true; std::set<std::string> ins;   /* the expr's var inputs */
                    std::function<void(const ExprP&)> chk = [&](const ExprP& e){
                        if (!e || !stable) return;
                        if (e->kind == EK::Var) {
                            ins.insert(e->name);
                            auto w = writes.find(e->name);
                            if ((w != writes.end() && w->second > 1) || addr.count(e->name)) stable = false;
                        }
                        chk(e->a); chk(e->b); chk(e->c); for (auto& a : e->args) chk(a);
                    };
                    chk(def.rhs);
                    if (!stable) continue;
                    /* every use must be in THIS block */
                    bool ext = false;
                    for (size_t bj = 0; bj < blocks.size() && !ext; ++bj) {
                        if (bj == bi) continue; Block& o = blocks[bj];
                        for (auto& s2 : o.stmts) if (count_var_reads(s2.rhs, nm) + count_lhs_addr_reads(s2.lhs, nm)) { ext = true; break; }
                        if (!ext && (count_var_reads(o.cond, nm) || count_var_reads(o.ret_value, nm) ||
                                     count_var_reads(o.ret_raw, nm) || count_var_reads(o.switch_var, nm) ||
                                     count_var_reads(o.tail_call, nm))) ext = true;
                    }
                    if (ext) continue;
                    bool used_term = count_var_reads(b.cond, nm) || count_var_reads(b.ret_value, nm) ||
                                     count_var_reads(b.ret_raw, nm) || count_var_reads(b.switch_var, nm) ||
                                     count_var_reads(b.tail_call, nm);
                    int lastst = -1;
                    for (size_t j = i + 1; j < b.stmts.size(); ++j)
                        if (count_var_reads(b.stmts[j].rhs, nm) + count_lhs_addr_reads(b.stmts[j].lhs, nm)) lastst = (int)j;
                    if (lastst < 0 && !used_term) continue;   /* no use (dead): leave to DSE */
                    int hz_end = used_term ? (int)b.stmts.size() : lastst;
                    bool hz = false;
                    for (int j = (int)i + 1; j < hz_end && !hz; ++j) {
                        Stmt& s = b.stmts[j];
                        /* an ASSIGNMENT to an input var between the def and a use changes
                         * the recomputed value (a single-def input can still be reassigned
                         * inside this window — `t=a1->f; a1=…; use t`). Always a hazard. */
                        if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && ins.count(s.lhs->name)) hz = true;
                        else if (rmem && has_call(s.rhs)) hz = true;             /* a call may write the cell */
                        else if (rmem && s.lhs && s.lhs->kind == EK::Mem) hz = true;  /* a store may alias */
                    }
                    if (hz) continue;
                    ExprP val = def.rhs;
                    for (size_t j = i + 1; j < b.stmts.size(); ++j) { subst_var(b.stmts[j].rhs, nm, val); subst_var(b.stmts[j].lhs, nm, val); }
                    subst_var(b.cond, nm, val); subst_var(b.ret_value, nm, val); subst_var(b.ret_raw, nm, val);
                    subst_var(b.switch_var, nm, val); subst_var(b.tail_call, nm, val);
                    def.kind = SK::Comment; def.label = "\x01inl";
                    changed = true;
                }
                b.stmts.erase(std::remove_if(b.stmts.begin(), b.stmts.end(),
                    [](const Stmt& s){ return s.kind == SK::Comment && s.label == "\x01inl"; }), b.stmts.end());
            }
        }
    }

    /* ===================== Magic-number division recovery (idiom #4) =====================
     * Reconstruct `x / C` and `x % C` from the compiler's multiply-high + shift idiom
     * (MSVC/GCC lower a constant divisor to `mulhi(x, M) [±x] >> s [+ signbit]`).
     *
     * SAFETY BY CONSTRUCTION: a candidate divisor is accepted ONLY when re-deriving the
     * magic number for it (Hacker's-Delight `magics`/`magicu`, validated by exhaustive
     * x-sweep) reproduces the OBSERVED magic constant M, shift s, AND correction shape
     * EXACTLY. A mismatch leaves the raw `__mulh` form untouched, so recognition can
     * never change behavior -- worst case it simply does not fire. This matters because
     * the behavioral corpus contains no magic division, so round-trip verification (not
     * the corpus) is the correctness guarantee here. */
    static const int64_t MD_DLIMIT = 100000;   /* search divisors up to this; larger => not folded */

    struct MSm { uint64_t M; int s; };          /* signed magic: M as bit pattern */
    struct MUm { uint64_t M; int s; int a; };   /* unsigned magic: +add-flag */
    static MSm md_magics(int64_t d, int bits) {
        if (bits == 32) {
            int32_t dd = (int32_t)d; uint32_t ad = (dd < 0) ? (uint32_t)(-(int64_t)dd) : (uint32_t)dd;
            const uint32_t two31 = 0x80000000u; uint32_t t = two31 + ((uint32_t)dd >> 31);
            uint32_t anc = t - 1 - t % ad; int p = 31;
            uint32_t q1 = two31/anc, r1 = two31 - q1*anc, q2 = two31/ad, r2 = two31 - q2*ad, delta;
            do { p++; q1 = 2*q1; r1 = 2*r1; if (r1 >= anc) { q1++; r1 -= anc; }
                 q2 = 2*q2; r2 = 2*r2; if (r2 >= ad) { q2++; r2 -= ad; } delta = ad - r2;
            } while (q1 < delta || (q1 == delta && r1 == 0));
            int32_t M = (int32_t)(q2 + 1); if (dd < 0) M = -M;
            return MSm{ (uint64_t)(uint32_t)M, p - 32 };
        } else {
            int64_t dd = d; uint64_t ad = (dd < 0) ? (uint64_t)(0 - (uint64_t)dd) : (uint64_t)dd;
            const uint64_t two63 = 0x8000000000000000ull; uint64_t t = two63 + ((uint64_t)dd >> 63);
            uint64_t anc = t - 1 - t % ad; int p = 63;
            uint64_t q1 = two63/anc, r1 = two63 - q1*anc, q2 = two63/ad, r2 = two63 - q2*ad, delta;
            do { p++; q1 = 2*q1; r1 = 2*r1; if (r1 >= anc) { q1++; r1 -= anc; }
                 q2 = 2*q2; r2 = 2*r2; if (r2 >= ad) { q2++; r2 -= ad; } delta = ad - r2;
            } while (q1 < delta || (q1 == delta && r1 == 0));
            int64_t M = (int64_t)(q2 + 1); if (dd < 0) M = -M;
            return MSm{ (uint64_t)M, p - 64 };
        }
    }
    static MUm md_magicu(uint64_t d, int bits) {
        if (bits == 32) {
            uint32_t dd = (uint32_t)d; int a = 0, p; uint32_t nc, delta, q1, r1, q2, r2;
            nc = (uint32_t)(-1) - (uint32_t)(-(int64_t)dd) % dd; p = 31;
            q1 = 0x80000000u/nc; r1 = 0x80000000u - q1*nc; q2 = 0x7FFFFFFFu/dd; r2 = 0x7FFFFFFFu - q2*dd;
            do { p++;
                 if (r1 >= nc - r1) { q1 = 2*q1 + 1; r1 = 2*r1 - nc; } else { q1 = 2*q1; r1 = 2*r1; }
                 if (r2 + 1 >= dd - r2) { if (q2 >= 0x7FFFFFFFu) a = 1; q2 = 2*q2 + 1; r2 = 2*r2 + 1 - dd; }
                 else                  { if (q2 >= 0x80000000u) a = 1; q2 = 2*q2;     r2 = 2*r2 + 1; }
                 delta = dd - 1 - r2;
            } while (p < 64 && (q1 < delta || (q1 == delta && r1 == 0)));
            return MUm{ (uint64_t)(uint32_t)(q2 + 1), p - 32, a };
        } else {
            uint64_t dd = d; int a = 0, p; uint64_t nc, delta, q1, r1, q2, r2;
            const uint64_t two63 = 0x8000000000000000ull, max63 = 0x7FFFFFFFFFFFFFFFull;
            nc = (uint64_t)(-1) - (uint64_t)(0 - dd) % dd; p = 63;
            q1 = two63/nc; r1 = two63 - q1*nc; q2 = max63/dd; r2 = max63 - q2*dd;
            do { p++;
                 if (r1 >= nc - r1) { q1 = 2*q1 + 1; r1 = 2*r1 - nc; } else { q1 = 2*q1; r1 = 2*r1; }
                 if (r2 + 1 >= dd - r2) { if (q2 >= max63) a = 1; q2 = 2*q2 + 1; r2 = 2*r2 + 1 - dd; }
                 else                  { if (q2 >= two63) a = 1; q2 = 2*q2;     r2 = 2*r2 + 1; }
                 delta = dd - 1 - r2;
            } while (p < 128 && (q1 < delta || (q1 == delta && r1 == 0)));
            return MUm{ q2 + 1, p - 64, a };
        }
    }

    /* single-def temp -> its pure defining rhs, so the matcher can peek through the CSE
     * temps the divisor idiom is split across (`t1 = __mulh(..); t2 = t1 >> 1; ...`). */
    std::map<std::string, ExprP> md_defs;
    void md_build_defs() {
        md_defs.clear();
        std::set<std::string> addr; collect_addr_taken(addr);
        std::map<std::string,int> wc;
        for (auto& b : blocks) for (auto& s : b.stmts)
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) wc[s.lhs->name]++;
        for (auto& b : blocks) for (auto& s : b.stmts)
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && s.rhs &&
                wc[s.lhs->name] == 1 && !addr.count(s.lhs->name) &&
                !array_locals.count(s.lhs->name) && !has_call(s.rhs))
                md_defs[s.lhs->name] = s.rhs;
    }
    ExprP md_resolve(const ExprP& e) {
        ExprP cur = e; int g = 0;
        while (cur && cur->kind == EK::Var && g++ < 32) {
            auto it = md_defs.find(cur->name);
            if (it == md_defs.end()) break;
            cur = it->second;
        }
        return cur ? cur : e;
    }
    ExprP md_strip(const ExprP& e) {   /* resolve temps + peel casts to the core value */
        ExprP c = md_resolve(e); int g = 0;
        while (c && c->kind == EK::Cast && c->a && g++ < 8) c = md_resolve(c->a);
        return c;
    }
    bool md_contains_mulhi(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Binary && (e->op == "mulh" || e->op == "umulh")) return true;
        if (e->kind == EK::Binary && e->op == ">>" && e->b && e->b->kind == EK::Const &&
            e->b->cval == 32 && e->a && e->a->kind == EK::Binary && e->a->op == "*") return true;
        if (md_contains_mulhi(e->a) || md_contains_mulhi(e->b) || md_contains_mulhi(e->c)) return true;
        for (auto& ar : e->args) if (md_contains_mulhi(ar)) return true;
        return false;
    }
    /* the __mulh/__umulh INTRINSIC specifically (needs a prototype); the 32-bit
     * `(*)>>32` form is plain C and does NOT. Used to recompute `used_mulh`. */
    bool md_has_mulh_intrinsic(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Binary && (e->op == "mulh" || e->op == "umulh")) return true;
        if (md_has_mulh_intrinsic(e->a) || md_has_mulh_intrinsic(e->b) || md_has_mulh_intrinsic(e->c)) return true;
        for (auto& ar : e->args) if (md_has_mulh_intrinsic(ar)) return true;
        return false;
    }
    /* Match a multiply-high node; extract core x, magic M (bit pattern), width (32/64),
     * and whether it is an UNSIGNED high-multiply. */
    bool md_match_mulhi(const ExprP& e0, ExprP& x, uint64_t& M, int& bits, bool& uns) {
        /* md_strip resolves temps AND peels casts, so a mulhi wrapped in extra
         * `(unsigned int)(...)`/temp layers (the add-1 unsigned form) still matches. */
        ExprP e = md_strip(e0);
        if (!e) return false;
        if (e->kind == EK::Binary && (e->op == "mulh" || e->op == "umulh")) {
            ExprP ra = md_strip(e->a), rb = md_strip(e->b);
            if (ra && ra->kind == EK::Const)      { M = (uint64_t)ra->cval; x = md_strip(e->b); }
            else if (rb && rb->kind == EK::Const) { M = (uint64_t)rb->cval; x = md_strip(e->a); }
            else return false;
            bits = 64; uns = (e->op == "umulh");
            return x != nullptr;
        }
        /* 32-bit: ((ll/ull)x * (ll/ull)M) >> 32  (the outer (int)/(unsigned) cast is
         * already peeled by md_strip, so signedness comes from the wide multiply). */
        if (e->kind == EK::Binary && e->op == ">>") {
            ExprP shb = md_strip(e->b);
            if (shb && shb->kind == EK::Const && shb->cval == 32) {
                ExprP prod = md_strip(e->a);
                if (prod && prod->kind == EK::Binary && prod->op == "*") {
                    ExprP ka = md_strip(prod->a), kb = md_strip(prod->b);
                    /* keep the RAW (unstripped) dividend so a `(int)v2` narrowing survives —
                     * md_strip would peel it, exposing an over-wide (width-8) temp and failing
                     * the 32-bit check below even though the DIVIDEND is 32-bit. */
                    if (ka && ka->kind == EK::Const)      { M = (uint64_t)ka->cval; x = prod->b; }
                    else if (kb && kb->kind == EK::Const) { M = (uint64_t)kb->cval; x = prod->a; }
                    else return false;
                    if (!x) return false;
                    /* A genuine 32-bit magic mulhi is `(int)(((ll)x32 * (ll)M32) >> 32)` — a
                     * 32->64 WIDENING multiply of a 32-bit dividend by a 32-bit magic. Peel
                     * only WIDENING casts (to width>=8); if what remains is <=4 bytes the
                     * dividend is 32-bit (even when the underlying var is a width-8 temp read
                     * as `(int)v2`). A residue still >4 bytes is a real 64-bit dividend -> do
                     * NOT fold (its low 32 bits could coincidentally match a magic). */
                    { ExprP xe = md_resolve(x);
                      while (xe && xe->kind == EK::Cast && xe->width >= 8 && xe->a) xe = md_resolve(xe->a);
                      if (!xe || xe->width > 4) return false;
                      x = xe; }
                    uint64_t hi = M >> 32;
                    if (hi != 0 && hi != 0xFFFFFFFFull) return false;
                    bits = 32; uns = prod->is_unsigned || e->is_unsigned;
                    return true;
                }
            }
        }
        return false;
    }
    /* brute-force the divisor and require an EXACT round-trip on (M, s, correction). */
    bool md_find_signed(uint64_t M, int s, int corr, int bits, int64_t& d_out) {
        for (int64_t ad = 3; ad <= MD_DLIMIT; ++ad)
            for (int sg = 0; sg < 2; ++sg) {
                int64_t d = sg ? -ad : ad;
                MSm mg = md_magics(d, bits);
                uint64_t Mo = (bits == 32) ? (uint32_t)M : M;
                uint64_t Md = (bits == 32) ? (uint32_t)mg.M : mg.M;
                if (Mo != Md || mg.s != s) continue;
                bool Mneg = (bits == 32) ? ((int32_t)mg.M < 0) : ((int64_t)mg.M < 0);
                int pred = (d > 0 && Mneg) ? +1 : (d < 0 && !Mneg) ? -1 : 0;
                if (pred != corr) continue;
                d_out = d; return true;
            }
        return false;
    }
    bool md_find_unsigned(uint64_t M, int s, int a, int bits, int64_t& d_out) {
        for (int64_t d = 3; d <= MD_DLIMIT; ++d) {
            MUm mg = md_magicu((uint64_t)d, bits);
            uint64_t Mo = (bits == 32) ? (uint32_t)M : M;
            uint64_t Md = (bits == 32) ? (uint32_t)mg.M : mg.M;
            if (mg.a == a && Mo == Md && mg.s == s) { d_out = d; return true; }
        }
        return false;
    }
    /* Recognize a quotient expression rooted at n; on success fill x/d/uns/wbytes. */
    bool md_match_quotient(const ExprP& n, ExprP& x_out, int64_t& d_out, bool& uns_out, int& wbytes) {
        if (!n || n->kind != EK::Binary) return false;
        /* SIGNED:  (CORE >> s)  +  ((unsigned)(CORE >> s) >> (W-1)) */
        if (n->op == "+") {
            for (int sw = 0; sw < 2; ++sw) {
                ExprP A = sw ? n->b : n->a;          /* the shifted quotient S */
                ExprP B = sw ? n->a : n->b;          /* the sign-bit add term */
                ExprP rB = md_resolve(B);
                if (!(rB && rB->kind == EK::Binary && rB->op == ">>")) continue;
                /* the sign-bit add MUST be a LOGICAL shift (`+1 if negative`, round toward
                 * zero); an arithmetic `>>` would be `-1 if negative` and NOT x/d. The
                 * unsignedness can live on the shift node OR on an unsigned operand cast. */
                ExprP rBa = md_resolve(rB->a);
                bool logical = rB->is_unsigned || (rBa && rBa->kind == EK::Cast && rBa->is_unsigned);
                if (!logical) continue;
                ExprP rBb = md_resolve(rB->b);
                if (!(rBb && rBb->kind == EK::Const && (rBb->cval == 31 || rBb->cval == 63))) continue;
                int W = (int)rBb->cval + 1;
                ExprP sbInner = (rBa && rBa->kind == EK::Cast) ? md_strip(rB->a) : rBa;
                /* compare STRIPPED forms: for s==0 the quotient part A is `(int)(mulhi)`
                 * while sbInner is the cast-peeled mulhi, so md_resolve(A) (casts kept)
                 * would spuriously differ by the `(int)`. */
                if (!exprEqual(sbInner, md_strip(A))) continue;
                ExprP S = md_resolve(A);
                int s; ExprP CORE;
                /* CAUTION: the mulhi ITSELF is `(M*x) >> 32`, a `>>` node. So the DIVISION
                 * shift `>> s` (s in [1,W-1]) is an OUTER shift only when S is NOT already a
                 * bare mulhi. Test mulhi FIRST -> s==0 (div by 3/6, magic 0x2aaaaaab/…). */
                { ExprP xt; uint64_t Mt; int mbt; bool mut;
                  if (md_match_mulhi(S, xt, Mt, mbt, mut)) { s = 0; CORE = S; }
                  else if (S && S->kind == EK::Binary && S->op == ">>" && !S->is_unsigned) {
                      ExprP Sb = md_resolve(S->b);
                      if (!(Sb && Sb->kind == EK::Const)) continue;
                      s = (int)Sb->cval; if (s < 0 || s >= W) continue;
                      CORE = md_resolve(S->a);
                  } else if (S && S->kind == EK::Binary && (S->op == "+" || S->op == "-")) {
                      s = 0; CORE = S;   /* s==0 with a mulhi±x correction inside CORE */
                  } else continue;
                }
                int corr = 0; ExprP x, mx; uint64_t M = 0; int mb = 0; bool mu = false;
                if (md_match_mulhi(CORE, x, M, mb, mu) && !mu) {
                    corr = 0;
                } else if (CORE && CORE->kind == EK::Binary && (CORE->op == "+" || CORE->op == "-")) {
                    if (md_match_mulhi(CORE->a, x, M, mb, mu) && !mu &&
                        exprEqual(md_strip(CORE->b), md_strip(x))) {   /* strip BOTH: see below */
                        corr = (CORE->op == "+") ? +1 : -1;
                    } else if (CORE->op == "+" && md_match_mulhi(CORE->b, x, M, mb, mu) && !mu &&
                               exprEqual(md_strip(CORE->a), x)) {
                        corr = +1;
                    } else continue;
                } else continue;
                if (mb != W) continue;
                int64_t d;
                if (md_find_signed(M, s, corr, W, d)) {
                    x_out = clone(x); d_out = d; uns_out = false; wbytes = W / 8; return true;
                }
            }
        }
        /* UNSIGNED (add-flag 0):  mulhi_u(x, M) >> s */
        if (n->op == ">>" && n->is_unsigned) {
            ExprP nb = md_resolve(n->b);
            if (nb && nb->kind == EK::Const) {
                int s = (int)nb->cval; ExprP x; uint64_t M = 0; int mb = 0; bool mu = false;
                if (md_match_mulhi(n->a, x, M, mb, mu) && mu && s >= 0 && s < mb) {
                    int64_t d;
                    if (md_find_unsigned(M, s, 0, mb, d)) {
                        x_out = clone(x); d_out = d; uns_out = true; wbytes = mb / 8; return true;
                    }
                }
            }
        }
        /* UNSIGNED (add-flag 1):  (T + ((x - T) >> 1)) >> (s-1),  T = mulhi_u(x, M).
         * The compiler wraps T and the subtraction in `(unsigned int)`/`(int)` casts,
         * so every structural step strips casts (md_strip) before matching. */
        if (n->op == ">>") {
            ExprP nb = md_resolve(n->b), sum = md_strip(n->a);
            if (nb && nb->kind == EK::Const && sum && sum->kind == EK::Binary && sum->op == "+") {
                int s1 = (int)nb->cval;
                for (int sw = 0; sw < 2; ++sw) {
                    ExprP T = sw ? sum->b : sum->a;
                    ExprP H = sw ? sum->a : sum->b;
                    ExprP rH = md_strip(H);
                    if (!(rH && rH->kind == EK::Binary && rH->op == ">>")) continue;
                    ExprP rHb = md_strip(rH->b);
                    if (!(rHb && rHb->kind == EK::Const && rHb->cval == 1)) continue;
                    ExprP sub = md_strip(rH->a);
                    if (!(sub && sub->kind == EK::Binary && sub->op == "-")) continue;
                    ExprP x; uint64_t M = 0; int mb = 0; bool mu = false;
                    if (!(md_match_mulhi(T, x, M, mb, mu) && mu)) continue;
                    /* sub = x - T : sub->b is the same mulhi as T, sub->a is x */
                    if (!exprEqual(md_strip(sub->b), md_strip(T))) continue;
                    /* STRIP BOTH SIDES. md_match_mulhi peels only WIDENING casts, so the
                     * dividend it hands back keeps any narrow one (`(unsigned int)v20`),
                     * while sub->a arrives fully stripped (`v20`) — comparing the two
                     * unstripped never matched, which is why the unsigned add-correction
                     * family (/7, /14, /28 — magic 0x24924925) never folded. NullWare's
                     * decryptor showed `v % 7` as a 200-char magic monster, four times in
                     * one function. */
                    if (!exprEqual(md_strip(sub->a), md_strip(x))) continue;
                    int s = s1 + 1; int64_t d;
                    if (s >= 1 && s <= mb && md_find_unsigned(M, s, 1, mb, d)) {
                        x_out = clone(x); d_out = d; uns_out = true; wbytes = mb / 8; return true;
                    }
                }
            }
        }
        return false;
    }
    /* Fold `X - (X / d) * d` -> `X % d` once the quotient has been recognized. */
    bool md_try_modulo(ExprP& e) {
        if (!(e->kind == EK::Binary && e->op == "-" && e->a && e->b)) return false;
        /* F2: `x - (x/d)*d` -> `x % d`. The compiler often leaves the subtrahend
         * UN-reduced as `(x/d * k) + (x/d * k)` (2k == d), so also accept `A + A`
         * (the doubled form) as `2*A`. md_strip peels the `(int)` casts around each. */
        ExprP rhs = md_strip(e->b);
        ExprP mul = rhs; int64_t extra = 1;
        if (rhs && rhs->kind == EK::Binary && rhs->op == "+" && rhs->a && rhs->b &&
            exprEqual(md_strip(rhs->a), md_strip(rhs->b))) {
            mul = md_strip(rhs->a); extra = 2;
        }
        if (!(mul && mul->kind == EK::Binary && mul->op == "*" && mul->a && mul->b)) return false;
        for (int sw = 0; sw < 2; ++sw) {
            ExprP c = md_strip(sw ? mul->a : mul->b);
            ExprP q = md_strip(sw ? mul->b : mul->a);
            if (!(c && c->kind == EK::Const)) continue;
            int64_t d = c->cval * extra;                    /* effective divisor */
            if (q && q->kind == EK::Binary && q->op == "/" && q->b && q->b->kind == EK::Const &&
                q->b->cval == d && q->a && exprEqual(md_strip(e->a), md_strip(q->a))) {
                bool uns = q->is_unsigned; int w = q->width ? q->width : 8;
                ExprP dv = mkConst(d, w, uns);
                dv->dec_hint = true;              /* a recovered divisor reads as `% 10` */
                e = mkBinary("%", clone(q->a), dv, w, uns);
                return true;
            }
        }
        return false;
    }
    bool md_changed = false;
    void md_rewrite(ExprP& e) {
        if (!e) return;
        md_rewrite(e->a); md_rewrite(e->b); md_rewrite(e->c);
        for (auto& ar : e->args) md_rewrite(ar);
        if (md_try_modulo(e)) { md_changed = true; return; }
        ExprP x; int64_t d; bool uns; int wb;
        if (md_match_quotient(e, x, d, uns, wb)) {
            /* A divisor recovered from a magic multiply is a human-scale number the
             * source wrote in decimal (`/ 10`, `/ 100`), never a bit pattern — so
             * force decimal rendering rather than inheriting the hex default. */
            ExprP dv = mkConst(d, wb, uns);
            dv->dec_hint = true;
            e = mkBinary("/", x, dv, wb, uns);
            md_changed = true;
        }
    }
    /* total_reads() now covers every block expr field (incl. tail_call/ret_raw), so
     * this is a plain alias kept for call-site clarity. */
    int md_total_reads(const std::string& nm) { return total_reads(nm); }
    void md_dce_mulhi() {   /* drop the now-orphaned pure `tN = __mulh(..)` temp stores */
        std::set<std::string> addr; collect_addr_taken(addr);
        bool ch = true;
        while (ch) {
            ch = false;
            for (auto& b : blocks) {
                auto& v = b.stmts;
                for (size_t i = 0; i < v.size(); ++i) {
                    Stmt& s = v[i];
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && s.rhs &&
                        !has_call(s.rhs) && !addr.count(s.lhs->name) &&
                        !array_locals.count(s.lhs->name) &&
                        md_contains_mulhi(s.rhs) && md_total_reads(s.lhs->name) == 0) {
                        v.erase(v.begin() + i); ch = true; break;
                    }
                }
                if (ch) break;
            }
        }
    }
    void recognize_magic_div() {
        md_build_defs();
        md_changed = false;
        /* The divisor idiom lives wherever the value flows: block statements, the
         * per-block return value / tail call (a straight-line function keeps its
         * result in ret_value, NOT stmts), branch conditions, and switch selectors. */
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { md_rewrite(s.rhs); md_rewrite(s.lhs); }
            md_rewrite(b.cond);
            md_rewrite(b.ret_value);
            md_rewrite(b.tail_call);
            md_rewrite(b.switch_var);
        }
        if (md_changed) {
            md_dce_mulhi();
            /* folding the last division may have removed every __mulh/__umulh: lower
             * used_mulh so no unused intrinsic prototype is emitted (never raise it).
             * Scan EVERY expression an intrinsic can survive in, incl. s.lhs (a store
             * address like `*(int*)(p + __umulh(i,M)) = v` keeps the intrinsic in the
             * lvalue) — missing it would drop a still-needed prototype -> compile error. */
            if (used_mulh) {
                bool any = false;
                for (auto& b : blocks) {
                    for (auto& s : b.stmts)
                        if (md_has_mulh_intrinsic(s.rhs) || md_has_mulh_intrinsic(s.lhs)) any = true;
                    if (md_has_mulh_intrinsic(b.ret_value) || md_has_mulh_intrinsic(b.tail_call) ||
                        md_has_mulh_intrinsic(b.cond) || md_has_mulh_intrinsic(b.switch_var)) any = true;
                }
                if (!any) used_mulh = false;
            }
        }
    }

    /* ---- post-typing idiom recognition (DS_IDIOM) ----
     * A pure expression-tree rewrite: touches no CFG edge/block/structured set, so the
     * goto count cannot move and no dominator/loop recompute is needed. Runs LAST (after
     * all typing + merge_short_circuit + struct recovery), before body emission.
     *
     * Idiom 1 — provably-unsigned range check:
     *     (x - lo) <=u range   ->   x >= lo && x <= hi     (hi = lo + range)
     * Exact for unsigned arithmetic (a<=u x<=u b  <=>  (x-a) <=u (b-a)); the extra
     * bound hi <= signed-max-of-width keeps it correct regardless of how x is rendered
     * (signed/unsigned) and lets char-literal recovery fire (e.g. `x >= '0' && x <= '9'`). */
    int idiom_node_count(const ExprP& e, int cap = 16) {
        if (!e || cap <= 0) return 0;
        int n = 1 + idiom_node_count(e->a, cap - 1) + idiom_node_count(e->b, cap - 1)
                  + idiom_node_count(e->c, cap - 1);
        for (auto& ar : e->args) n += idiom_node_count(ar, cap - 1);
        return n;
    }
    ExprP match_range_check(const ExprP& e) {
        static const bool dbg = std::getenv("DS_IDIOM_DBG") != nullptr;
        if (!e || e->kind != EK::Binary || e->is_float || !e->is_unsigned) return e;
        const std::string& op = e->op;
        /* conjunction for the IN-range polarities (<=,<), disjunction for OUT (>,>=). */
        bool conj;
        if      (op == "<=" || op == "<")  conj = true;
        else if (op == ">"  || op == ">=") conj = false;
        else return e;
        ExprP S = e->a, R = e->b;
        if (!isConst(R) || R->is_float || R->cval < 0) return e;
        /* hi = inclusive upper bound of the IN-range interval [lo, hi]. */
        int64_t Rc = R->cval;
        if (!S || S->kind != EK::Binary || S->op != "-" || !isConst(S->b) || S->b->is_float) return e;
        int64_t lo = S->b->cval;
        if (lo <= 0) return e;                                 /* lo == 0 degenerates to x cmp hi */
        ExprP x = S->a;
        if (!x || isConst(x) || has_call(x)) return e;         /* no side-effecting double-eval */
        /* width comes from the OPERANDS (the subtraction), not the compare (bool) result. */
        int w = S->width ? S->width : (x->width ? x->width : 4);
        /* inclusive upper bound of the in-range interval, per op:
         *   <= R : [lo, lo+R]      <  R : [lo, lo+R-1]
         *   >  R : complement of [lo, lo+R]     >= R : complement of [lo, lo+R-1]  */
        int64_t hi = (op == "<=" || op == ">") ? lo + Rc : lo + Rc - 1;
        if (hi <= lo) return e;                                /* degenerate single-value range */
        int64_t smax = (w == 1) ? 0x7f : (w == 2) ? 0x7fff : 0x7fffffffLL;  /* qword clamped */
        if (dbg) fprintf(stderr, "[IDIOM]  cand op=%s lo=0x%llx hi=0x%llx w=%d conj=%d nc=%d\n",
                         op.c_str(), (unsigned long long)lo, (unsigned long long)hi, w, (int)conj, idiom_node_count(x));
        if (hi > smax) return e;                               /* signed-safe: both renderings agree */
        if (idiom_node_count(x) > 8) return e;                 /* don't duplicate a large subtree */
        if (dbg) fprintf(stderr, "[IDIOM]  >>> MATCH (%s)\n", conj ? "&&" : "||");
        ExprP lo_c = mkConst(lo, w, e->is_unsigned), hi_c = mkConst(hi, w, e->is_unsigned);
        if (conj) {   /* x >= lo && x <= hi */
            ExprP ge = mkBinary(">=", clone(x), lo_c, w, e->is_unsigned);
            ExprP le = mkBinary("<=", clone(x), hi_c, w, e->is_unsigned);
            return mkBinary("&&", ge, le, 4, false);
        }
        /* x < lo || x > hi */
        ExprP lt = mkBinary("<", clone(x), lo_c, w, e->is_unsigned);
        ExprP gt = mkBinary(">", clone(x), hi_c, w, e->is_unsigned);
        return mkBinary("||", lt, gt, 4, false);
    }
    void idiom_rewrite(ExprP& e) {
        if (!e) return;
        idiom_rewrite(e->a); idiom_rewrite(e->b); idiom_rewrite(e->c);
        for (auto& ar : e->args) idiom_rewrite(ar);
        e = match_range_check(e);
    }
    void recognize_idioms() {
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { idiom_rewrite(s.rhs); idiom_rewrite(s.lhs); }
            idiom_rewrite(b.cond);
            idiom_rewrite(b.ret_value);
            idiom_rewrite(b.tail_call);
            idiom_rewrite(b.switch_var);
        }
    }

    void collect_var_info() {
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                scan_types(s.lhs, true);
                scan_types(s.rhs, false);
            }
            scan_types(b.cond, false);
            scan_types(b.ret_value, false);
            scan_types(b.switch_var, false);
            scan_types(b.tail_call, false);
        }
    }

    /* Pointer-only re-marking: walk every expression and run mark_ptr_in_addr on each
     * Mem's address, WITHOUT scan_types' var_width max-wins bump. Used as a LATE pass
     * (after CSE mints its temps) so a hoisted `tN = glob+off` that is dereferenced
     * gets typed a pointer — but a re-run of full collect_var_info would also widen a
     * `float` accumulator to `double` (max-wins width), silently changing FP precision
     * and failing the behavioral float corpus (arr_sum/arr_normalize01). This skips
     * that side effect. */
    /* Mark ONLY a "clean pointer base": a bare var, or `(cast)var ± CONSTANT`. Unlike
     * mark_ptr_in_addr this REFUSES `var + <non-const>` — because the non-const side may
     * itself be the real base (a stack array or another pointer), and marking BOTH makes
     * `p + q` = C2110 "cannot add two pointers" (fn_00039aa0: `(char*)t817 + (s4+0x24)`
     * where t817 is a scaled index `(float*)(i*4)` and s4 is the array base). The late
     * pass only needs the unambiguous `tN = glob+off; *(T*)(tN ± const)` shape anyway. */
    void mark_clean_ptr_base(const ExprP& e, int elem_w, bool elem_uns, bool elem_float) {
        if (!e) return;
        if (e->kind == EK::Var) {
            if (array_locals.count(e->name)) return;
            mark_ptr_in_addr(e, elem_w, elem_uns, elem_float, false);
            return;
        }
        if (e->kind == EK::Cast) { mark_clean_ptr_base(e->a, elem_w, elem_uns, elem_float); return; }
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-")) {
            if (e->b && e->b->kind == EK::Const) { mark_clean_ptr_base(e->a, elem_w, elem_uns, elem_float); return; }
            if (e->a && e->a->kind == EK::Const && e->op == "+") { mark_clean_ptr_base(e->b, elem_w, elem_uns, elem_float); return; }
        }
        /* var+var / var+arrayexpr / scaled index / anything else: ambiguous — do not mark. */
    }
    void mark_deref_pointers_expr(const ExprP& e) {
        if (!e) return;
        if (e->kind == EK::Mem)
            mark_clean_ptr_base(e->a, e->width ? e->width : 1, e->is_unsigned, e->is_float);
        mark_deref_pointers_expr(e->a);
        mark_deref_pointers_expr(e->b);
        mark_deref_pointers_expr(e->c);
        for (auto& ar : e->args) mark_deref_pointers_expr(ar);
    }
    void mark_late_deref_pointers() {
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { mark_deref_pointers_expr(s.lhs); mark_deref_pointers_expr(s.rhs); }
            mark_deref_pointers_expr(b.cond);
            mark_deref_pointers_expr(b.ret_value);
            mark_deref_pointers_expr(b.switch_var);
            mark_deref_pointers_expr(b.tail_call);
        }
    }

    std::set<std::string> conflict_raw_vars;   /* declare as raw `long long` */
    /* A variable declared as a POINTER (mis-inferred) but ASSIGNED a float value
     * — `int* t10 = <float t8>` — is a hard C2440 with no valid cast (float and
     * pointer are unrelated types). It arises from a mis-merged register: a gp
     * pointer live-range and an xmm float live-range collapsed into one temp (an
     * SSE min/max search shuttling point coordinates). We can't cleanly un-merge
     * here, but declaring the temp as the RAW 8-byte `long long` register it
     * physically is makes EVERY assignment/use compile through the existing
     * conversion+cast paths (float->ll and ptr->ll are /w-suppressed warnings, not
     * errors), eliminating the hard error. Only touches pointer-typed vars that
     * receive a float value — all already-broken — so it can never regress
     * working code. */
    void mark_type_conflict_raw() {
        conflict_raw_vars.clear();
        /* does the expression render/declare as a FLOAT value? (a float var via
         * var_is_float OR force_float_vars, an is_float expr/deref, or a cast of
         * one). A float* pointer is NOT a float value. */
        std::function<bool(const ExprP&)> is_float_val = [&](const ExprP& x) -> bool {
            if (!x) return false;
            if (expr_is_pointer(x)) return false;
            if (x->is_float) return true;
            if (x->kind == EK::Var) {
                const std::string& n = x->name;
                return (var_is_float.count(n) && var_is_float[n]) || force_float_vars.count(n);
            }
            if (x->kind == EK::Cast) return is_float_val(x->a);
            return false;
        };
        /* an ADDRESS value: a pointer, an &x, a stack array, or +/- arithmetic on
         * one (`s7 + 12`). Used for the symmetric conflict below. */
        std::function<bool(const ExprP&)> is_addr_val = [&](const ExprP& x) -> bool {
            if (!x) return false;
            if (expr_is_pointer(x) || x->kind == EK::AddrOf) return true;
            if (x->kind == EK::Var && array_locals.count(x->name)) return true;
            if (x->kind == EK::Binary && (x->op == "+" || x->op == "-"))
                return is_addr_val(x->a) || is_addr_val(x->b);
            if (x->kind == EK::Cast) return is_addr_val(x->a);
            return false;
        };
        /* SYMMETRIC conflict: a FLOAT-typed var that receives a POINTER/address
         * value (`float v4 = s7 + 12`, C2440 char*->float) — the same mis-merged
         * register the other way round. Declare it raw so both the address and any
         * float assignment compile as conversions. */
        for (auto& b : blocks)
            for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs)
                    continue;
                const std::string& t = s.lhs->name;
                bool decl_float = (var_is_float.count(t) && var_is_float[t]) ||
                                  force_float_vars.count(t);
                /* a float-typed var that receives an ADDRESS (`v4 = s7+12`) or an
                 * 8-byte QWORD int/pointer LOAD (`t5 = *(long long*)(a1+0x2a8)`,
                 * later returned as a pointer) is the mis-merge the other way — the
                 * value is not a float. Raw it. (A 4-byte int load into a float is
                 * left alone: that is a legitimate int->float conversion.) */
                bool nonfloat_qword = s.rhs->kind == EK::Mem && !s.rhs->is_float &&
                                      s.rhs->width >= 8;
                if (decl_float && (is_addr_val(s.rhs) || nonfloat_qword))
                    conflict_raw_vars.insert(t);
            }
        /* PARAM mis-type: a float/double parameter that is really a pointer/integer
         * arriving in an xmm register (the mis-merged register the other way) — the
         * WHOLE value, not a float. Detect it from POINTER/INTEGER-only uses that a
         * genuine float param never exhibits, and declare the PARAM raw `long long`
         * so subtraction (`a2 - a1`), masks (`& -32`), subscripts, derefs and
         * compares involving it compile. The corpus float DLLs (floattorture,
         * geometry) gate this so a real float param is never demoted. */
        auto flt_param = [&](const ExprP& x) -> std::string {
            if (!x || x->kind != EK::Var) return "";
            const std::string& n = x->name;
            bool isp = n.size() >= 2 && n[0] == 'a' && isdigit((unsigned char)n[1]);
            bool isf = (var_is_float.count(n) && var_is_float[n]) || force_float_vars.count(n);
            return (isp && isf) ? n : "";
        };
        /* (a) copied wholesale into a pointer variable (`t8 = a1`, `t2 = (T*)a4`) —
         * unwrap any reinterpret cast the lifter inserted for a double->ptr move. */
        for (auto& b : blocks)
            for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs)
                    continue;
                if (!(var_pointer.count(s.lhs->name) && var_pointer[s.lhs->name])) continue;
                ExprP rv = s.rhs;
                while (rv && rv->kind == EK::Cast) rv = rv->a;
                std::string p = flt_param(rv);
                if (!p.empty()) conflict_raw_vars.insert(p);
            }
        /* (b) used in a POINTER/INTEGER-only operator: a bitwise/shift/mod on it, or
         * `+`/`-` against a NON-float (pointer/int) sibling — i.e. address
         * arithmetic like `(a2 - a1) & -32` where a2 is a `long long` end pointer. */
        std::function<void(const ExprP&)> scan_pmis = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Binary) {
                const std::string& o = e->op;
                std::string p;
                if (o=="&"||o=="|"||o=="^"||o=="<<"||o==">>"||o=="%") {
                    if (!(p = flt_param(e->a)).empty()) conflict_raw_vars.insert(p);
                    if (!(p = flt_param(e->b)).empty()) conflict_raw_vars.insert(p);
                } else if (o=="+"||o=="-") {
                    if (!(p = flt_param(e->a)).empty() && !is_float_val(e->b))
                        conflict_raw_vars.insert(p);
                    if (!(p = flt_param(e->b)).empty() && !is_float_val(e->a))
                        conflict_raw_vars.insert(p);
                }
            }
            scan_pmis(e->a); scan_pmis(e->b); scan_pmis(e->c);
            for (auto& ar : e->args) scan_pmis(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan_pmis(s.lhs); scan_pmis(s.rhs); }
            scan_pmis(b.cond);
        }
        for (int iter = 0; iter < 8; ++iter) {   /* fixpoint: a conflicted var may feed another */
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            bool changed = false;
            for (auto& b : blocks)
                for (auto& s : b.stmts) {
                    if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs)
                        continue;
                    const std::string& t = s.lhs->name;
                    if (conflict_raw_vars.count(t)) continue;
                    if (!(var_pointer.count(t) && var_pointer[t])) continue;   /* declared a pointer */
                    /* If the var is already known-float (var_is_float set, from a float
                     * EXPRESSION assignment), decl_type's float-wins rule ALREADY
                     * declares it `float` correctly — do NOT override to raw `long
                     * long` (that truncates a genuine float sum: vec2_add's `t1 =
                     * a.x+b.x`). conflict_raw is only for a pointer var that receives
                     * float BITS a bare copy never marked float (fn_00011470's t10). */
                    if (var_is_float.count(t) && var_is_float[t]) continue;
                    if (is_float_val(s.rhs)) { conflict_raw_vars.insert(t); changed = true; }
                }
            if (!changed) break;
        }
    }

    bool ret_is_pointer = false;
    bool ret_is_float = false;     /* function returns float/double in xmm0 */
    bool ret_conflict_raw = false; /* returns BOTH a float and a pointer -> raw ll */
    bool ret_is_unsigned = false;  /* integer return computed by unsigned ops */
    int  ret_ptr_elem_w = 0;
    bool ret_ptr_elem_uns = false;
    int  ret_small_w = 0;          /* 1/2 when every path returns a byte/short value */
    bool ret_small_uns = false;    /* signedness of that narrow return */
    /* When every return path hands back the SAME recovered-struct pointer, the return type
     * is that struct pointer — not the scalar element type of its first field. Without this,
     * `Vec3* make(Vec3* out, ...) { out->x = ..; return out; }` declares `float*` (field 0's
     * width) and casts the return `(float*)out`: the declared type contradicts the returned
     * expression, and only that inserted cast keeps it compiling.
     *
     * Computed LAZILY, at render time, rather than as a pipeline pass. param_structs does not
     * exist until recover_struct_layouts(), which runs ~75 lines AFTER recover_return_type() —
     * a pass placed at the natural-looking spot reads an empty map and silently never fires
     * (which is exactly what the first cut of this did). Deciding it on demand means it cannot
     * be wrong about ordering, and the struct tags are final by then.
     * Kill switch: DS_NO_RETSTRUCT. */
    bool ret_struct_done = false;
    std::string ret_struct_type;
    const std::string& ret_struct_ty() {
        if (ret_struct_done) return ret_struct_type;
        ret_struct_done = true;
        ret_struct_type.clear();
        if (std::getenv("DS_NO_RETSTRUCT")) return ret_struct_type;
        if (!used_return || !ret_is_pointer || ret_conflict_raw || ret_is_float)
            return ret_struct_type;
        std::string agreed;
        bool any = false;
        for (auto& b : blocks) {
            /* a tail call returns the CALLEE's value, which this test says nothing about */
            if (b.tail_call) return ret_struct_type;
            if (!b.has_ret_value || !b.ret_value) continue;
            ExprP m = b.ret_value;
            while (m && m->kind == EK::Cast && m->a) m = m->a;   /* `return (T*)a1` */
            if (!m || m->kind != EK::Var) return ret_struct_type;
            auto si = param_structs.find(m->name);
            if (si == param_structs.end()) return ret_struct_type;
            std::string t = std::string(si->second.is_class && !si->second.cls_kw_struct
                                        ? "class " : "struct ") + si->second.tag + "*";
            /* EVERY path must agree. A function returning either a Node* or a Leaf* has no
             * single struct return type, and naming one of them would be a lie. */
            if (agreed.empty()) agreed = t;
            else if (agreed != t) return ret_struct_type;
            any = true;
        }
        if (any) ret_struct_type = agreed;
        return ret_struct_type;
    }

    /* True if `e` is a pointer-typed value: an address (AddrOf), a pointer
     * variable, or pointer arithmetic with a pointer-var operand. Used to
     * recover pointer-returning functions whose RAX-at-ret holds an element
     * address (e.g. my_strchr `return &s[i]`). */
    bool expr_is_pointer(const ExprP& e, int* elem_w = nullptr, bool* elem_u = nullptr) {
        if (!e) return false;
        if (e->kind == EK::AddrOf) return true;
        if (e->kind == EK::Var) {
            auto it = var_pointer.find(e->name);
            if (it != var_pointer.end() && it->second) {
                if (elem_w) { auto w = ptr_elem_width.find(e->name);
                    if (w != ptr_elem_width.end()) *elem_w = w->second; }
                if (elem_u) { auto u = ptr_elem_uns.find(e->name);
                    if (u != ptr_elem_uns.end()) *elem_u = u->second; }
                return true;
            }
            return false;
        }
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-"))
            return expr_is_pointer(e->a, elem_w, elem_u) ||
                   expr_is_pointer(e->b, elem_w, elem_u);
        if (e->kind == EK::Cast) return expr_is_pointer(e->a, elem_w, elem_u);
        /* G4: a load of a `void*` struct field is a pointer value (mirrors renders_as_pointer's
         * EK::Mem arm). elem_w stays unset — a void* field has no element type, so element-scaled
         * subscripting never fires on it (is_ptr_base rejects Mem regardless). */
        if (e->kind == EK::Mem) return is_struct_ptr_field(e);
        return false;
    }

    /* Late return-type recovery: if any ret holds a pointer value, the function
     * returns a pointer. Promote the return to 8 bytes and strip the bogus
     * `(int)` truncation the initial sig-table width forced. This fixes
     * pointer-returning functions (strchr/strcpy/strcat) the linear sig-table
     * scan mis-sized as `int` because the last RAX write before a merged ret was
     * a 32-bit `xor eax,eax` on a different path. */
    /* Is `e` a value of POINTER type (not just "contains a pointer")? `ptr + i`
     * and `ptr - i` are pointers; `ptr - ptr` is a ptrdiff (NOT a pointer); a
     * copy or cast of a pointer is a pointer. Stricter than expr_is_pointer so
     * the propagation below never mistypes an integer temp. */
    bool ptr_value_of(const ExprP& e, int* ew, bool* eu) {
        if (!e) return false;
        if (e->kind == EK::AddrOf) return true;
        if (e->kind == EK::Var) {
            auto it = var_pointer.find(e->name);
            if (it == var_pointer.end() || !it->second) return false;
            if (ew) { auto w = ptr_elem_width.find(e->name); if (w != ptr_elem_width.end()) *ew = w->second; }
            if (eu) { auto u = ptr_elem_uns.find(e->name);   if (u != ptr_elem_uns.end())   *eu = u->second; }
            return true;
        }
        if (e->kind == EK::Cast) return ptr_value_of(e->a, ew, eu);
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-")) {
            /* capture the element width from WHICHEVER side is the pointer — a
             * `offset + base` (pointer on the right) must still carry base's elem
             * width, else the temp is marked a pointer but with no width and decl_type
             * degrades it back to `long long` (roadmap #1: address arithmetic hoisted
             * to a temp loses its pointer type). */
            int ewa=0, ewb=0; bool eua=false, eub=false;
            bool ap = ptr_value_of(e->a, &ewa, &eua);
            bool bp = ptr_value_of(e->b, &ewb, &eub);
            if (e->op == "-") {                        /* ptr - int only */
                if (ap && !bp) { if (ew) *ew = ewa; if (eu) *eu = eua; return true; }
                return false;
            }
            if (ap && !bp) { if (ew) *ew = ewa; if (eu) *eu = eua; return true; }
            if (bp && !ap) { if (ew) *ew = ewb; if (eu) *eu = eub; return true; }
            return false;                              /* neither / both a pointer */
        }
        return false;
    }

    /* Propagate pointer-ness through assignments: a temp assigned a pointer value
     * (`t = base + i`) is itself a pointer. Without this a returned pointer held
     * in a temp (`t1 = s + i; return t1;`) is never recognised, so the return
     * type stays `int` and `return (int)t1` TRUNCATES the 64-bit pointer to 32
     * bits — every my_strchr/my_strrchr-style result was wrong (50000/50000). */
    void propagate_pointer_types() {
        bool changed = true; int guard = 0;
        while (changed && guard++ < 8) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) {
                    if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var) continue;
                    const std::string& nm = s.lhs->name;
                    if (array_locals.count(nm)) continue;
                    if (var_pointer.count(nm) && var_pointer[nm]) continue;
                    int ew = 0; bool eu = false;
                    if (s.rhs && ptr_value_of(s.rhs, &ew, &eu)) {
                        var_pointer[nm] = true; var_is_ll[nm] = true;
                        if (ew > 0 && !ptr_elem_width.count(nm)) {
                            ptr_elem_width[nm] = ew; ptr_elem_uns[nm] = eu;
                        }
                        changed = true;
                    }
                }
            }
        }
    }

    /* Is `e` a value of FLOATING-POINT type? A scalar-SSE op / float literal /
     * float-typed deref already carries is_float; a copy/cast/ternary of a float
     * is float; `+ - * /` with a float operand yields a float. Conservative — it
     * never crosses a (int)-cast boundary (cvttss2si), so an int that was
     * converted FROM a float stays int. */
    /* Float WIDTH of a value: 4 (single, `ss`/`*(float*)`/`4.0f`), 8 (double,
     * `sd`/`*(double*)`), or 0 (not float). Tracking the width — not just "is
     * float" — is what keeps a single-precision chain `float` instead of widening
     * it to `double`. A binary takes the wider operand; a cvtss2sd/cvtsd2ss cast
     * carries the cast's own width. */
    int float_width_of(const ExprP& e) {
        if (!e) return 0;
        /* a comparison (`a > b`, `x == y`) yields a boolean int 0/1 — NEVER a float,
         * even when its operands are float (the node may carry is_float from the FP
         * compare). Without this the result temp is mis-declared `float`
         * (`float t7 = 0.0f > t6;` then used as `t7 ? .. : ..`). */
        if (e->kind == EK::Binary &&
            (e->op=="<"||e->op==">"||e->op=="<="||e->op==">="||e->op=="=="||e->op=="!="))
            return 0;
        if (e->is_float) return e->width >= 8 ? 8 : 4;
        if (e->kind == EK::Var) {
            if (var_is_float.count(e->name) && var_is_float[e->name])
                return (var_width.count(e->name) && var_width[e->name] >= 8) ? 8 : 4;
            return 0;
        }
        if (e->kind == EK::Cast) return e->is_float ? (e->width >= 8 ? 8 : 4) : 0;
        if (e->kind == EK::Ternary) {
            int a = float_width_of(e->b), b = float_width_of(e->c);
            return a ? a : b;
        }
        if (e->kind == EK::Binary &&
            (e->op=="+"||e->op=="-"||e->op=="*"||e->op=="/")) {
            int a = float_width_of(e->a), b = float_width_of(e->b);
            return (a || b) ? std::max(a, b) : 0;
        }
        return 0;
    }
    bool float_value_of(const ExprP& e) { return float_width_of(e) != 0; }

    /* Recursively re-tag bare INTEGER Const nodes as float when they sit in a
     * provably-float position: a `.rdata` float constant (`movss xmm,[rip+C]`) is
     * folded to its raw bit pattern Const, and the is_float tag set at lift time
     * (as_float) is sometimes lost across copy-prop / CSE — so `float t = 0x40800000;`
     * (which assigns 1082130432.0f, NOT 4.0f) escapes. Marking the Const float makes
     * render_const reinterpret the bits as `4.0f`. `fw` is the float width (4/8) of
     * the surrounding context. Only a leaf Const is retagged (the value IS the float);
     * we do NOT descend into mixed integer arithmetic where a const is a real scale. */
    void retag_float_const(ExprP& e, int fw) {
        if (!e) return;
        if (e->kind == EK::Const) {
            if (!e->is_float) { e->is_float = true; e->width = (fw >= 8) ? 8 : 4; }
            return;
        }
        /* a ternary selects between two float values — both arms are float consts */
        if (e->kind == EK::Ternary) { retag_float_const(e->b, fw); retag_float_const(e->c, fw); return; }
        /* a float arithmetic op: a Const operand is a real float literal too */
        if (e->kind == EK::Binary &&
            (e->op=="+"||e->op=="-"||e->op=="*"||e->op=="/")) {
            if (e->a && e->a->kind == EK::Const) retag_float_const(e->a, fw);
            if (e->b && e->b->kind == EK::Const) retag_float_const(e->b, fw);
        }
    }
    /* Collect the max float-width at which a bare Var is a DIRECT operand of scalar-FP
     * arithmetic (`fexpr + v`, `v * fexpr`, ...). as_float never taints Vars, and a
     * genuine int->float conversion always carries a cvtsi2ss/sd `(cast)` node — so a
     * BARE var in a float `+ - * /` provably holds a float VALUE, not an int. */
    void rescue_float_scan(const ExprP& e, std::map<std::string,int>& fu) {
        if (!e) return;
        if (e->kind == EK::Binary &&
            (e->op=="+"||e->op=="-"||e->op=="*"||e->op=="/")) {
            if (e->a && e->a->kind == EK::Var) { int w=float_width_of(e->b); if (w) { int& c=fu[e->a->name]; if (w>c) c=w; } }
            if (e->b && e->b->kind == EK::Var) { int w=float_width_of(e->a); if (w) { int& c=fu[e->b->name]; if (w>c) c=w; } }
        }
        rescue_float_scan(e->a, fu); rescue_float_scan(e->b, fu); rescue_float_scan(e->c, fu);
        for (auto& ar : e->args) rescue_float_scan(ar, fu);
    }
    /* A frame/phi slot whose EVERY definition is a plain integer Const, yet which is
     * consumed directly (no cast) by scalar-FP arithmetic, holds a float VALUE whose
     * bit pattern reached an int-typed SSA slot: a `movss xmm,[rip+C]` .rdata constant
     * that lost its is_float across a select/phi merge (fn_0000e6f0's `v3 = -1082130432`
     * = 0xBF800000 = -1.0f, later `-0.33333334f - v3`). Left int, the arithmetic is
     * numerically WRONG. Retype the slot float so retype_float_constants reinterprets
     * its const defs as float literals. Guard is deliberately tight (all defs const AND
     * a bare-Var float-arith use) so a genuine integer never flips. */
    void rescue_const_float_vars() {
        std::map<std::string,int> defc;      /* def count per var */
        std::map<std::string,bool> allconst; /* every def is a plain int Const */
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
            const std::string& n = s.lhs->name;
            defc[n]++;
            bool c = (s.rhs->kind == EK::Const && !s.rhs->is_float);
            auto it = allconst.find(n);
            if (it == allconst.end()) allconst[n] = c; else it->second = it->second && c;
        }
        std::map<std::string,int> fu;
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { rescue_float_scan(s.lhs, fu); rescue_float_scan(s.rhs, fu); }
            rescue_float_scan(b.cond, fu); rescue_float_scan(b.ret_value, fu); rescue_float_scan(b.switch_var, fu);
        }
        for (auto& kv : fu) {
            const std::string& n = kv.first;
            if (var_pointer.count(n) && var_pointer[n]) continue;
            if (var_is_float.count(n) && var_is_float[n]) continue;
            if (!defc.count(n) || defc[n] == 0) continue;
            if (!allconst.count(n) || !allconst[n]) continue;
            var_is_float[n] = true;
            var_width[n] = (kv.second >= 8) ? 8 : 4;
            var_is_ll[n] = (kv.second >= 8);
        }
    }
    /* A store `*(int32_t*)ADDR = <int const>` whose ADDR is ALSO accessed as a
     * float (movss/movsd) somewhere in the SAME function is writing a float bit-
     * pattern into a float slot (`mov dword[p+0x1c],0xBF800000` sitting beside
     * `movss [p+0x1c],xmm`). Mark the int store's lvalue float so
     * retype_float_constants reinterprets the immediate as its float literal
     * (0xBF800000 becomes -1.0f). This is BIT-PRESERVING: `*(float*)p = -1.0f`
     * writes the identical 4 bytes as `*(int32_t*)p = 0xBF800000`, so it is always
     * correct C. The guard requires exprEqual float evidence at the SAME address
     * and width, so a genuine integer slot is never flipped. */
    void float_bits_store_by_alias() {
        std::vector<std::pair<ExprP,int>> faddrs;   /* (address, width) of float mem accesses */
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Mem && e->is_float && e->a &&
                (e->width == 4 || e->width == 8))
                faddrs.push_back({e->a, e->width >= 8 ? 8 : 4});
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.switch_var);
        }
        if (faddrs.empty()) return;
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Mem || !s.lhs->a) continue;
            if (s.lhs->is_float) continue;
            if (s.lhs->width != 4 && s.lhs->width != 8) continue;
            if (!s.rhs || s.rhs->kind != EK::Const || s.rhs->is_float) continue;
            int w = s.lhs->width >= 8 ? 8 : 4;
            for (auto& fa : faddrs) {
                if (fa.second == w && exprEqual(fa.first, s.lhs->a)) {
                    s.lhs->is_float = true;
                    break;
                }
            }
        }
    }
    void retype_float_constants() {
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || !s.rhs) continue;
            int fw = 0;
            if (s.lhs->kind == EK::Var) {
                const std::string& nm = s.lhs->name;
                if (var_is_float.count(nm) && var_is_float[nm] &&
                    !(var_pointer.count(nm) && var_pointer[nm]))
                    fw = (var_width.count(nm) && var_width[nm] >= 8) ? 8 : 4;
            } else if (s.lhs->kind == EK::Mem && s.lhs->is_float) {
                fw = (s.lhs->width >= 8) ? 8 : 4;
            }
            if (fw) retag_float_const(s.rhs, fw);
        }
    }

    /* Propagate float-ness through the temp SSA: a temp defined from a float
     * value is itself float, to a fixpoint (so it flows through phi merges); then
     * a pointer that a float value is stored through is a float*. Without this the
     * SSE ops decode correctly but the temps and the destination pointer stay
     * `long long` (the cb50/cee0 "float math in long long temps" lag). */
    /* A temp whose EVERY definition is a comparison (`t = a > b`) holds a boolean
     * int 0/1, so it must not be float-typed — the lift sometimes marks it float
     * (force_float) because the setcc result shared an XMM-class register with a
     * neighbouring float compare (`t7 = 0.0f > t6;` used as `t7 ? .. : ..`). Demote
     * such temps to `int`. Conservative: any NON-comparison def leaves it alone. */
    void demote_comparison_temps() {
        auto is_cmp = [](const ExprP& e) {
            return e && e->kind == EK::Binary &&
                (e->op=="<"||e->op==">"||e->op=="<="||e->op==">="||e->op=="=="||e->op=="!=");
        };
        std::map<std::string,bool> cmp_def, other_def;
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
            if (is_cmp(s.rhs)) cmp_def[s.lhs->name] = true;
            else               other_def[s.lhs->name] = true;
        }
        for (auto& kv : cmp_def) {
            const std::string& n = kv.first;
            if (other_def.count(n)) continue;              /* mixed def — leave it */
            if (var_pointer.count(n) && var_pointer[n]) continue;
            var_is_float.erase(n); force_float_vars.erase(n);
            var_width[n] = 4; var_is_ll[n] = false;        /* int */
        }
    }

    void propagate_float_types() {
        bool changed = true; int guard = 0;
        while (changed && guard++ < 8) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            changed = false;
            for (auto& b : blocks) for (auto& s : b.stmts) {
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var) continue;
                const std::string& nm = s.lhs->name;
                if (var_pointer.count(nm) && var_pointer[nm]) continue;   /* pointer wins */
                int fw = s.rhs ? float_width_of(s.rhs) : 0;
                if (!fw) continue;
                if (!var_is_float.count(nm) || !var_is_float[nm]) {
                    var_is_float[nm] = true; changed = true;
                }
                /* set the FLOAT width (4 vs 8) — overriding the phi-temp default
                 * of 8 so a single-precision temp declares `float`, not `double`. */
                if (var_width[nm] != fw) { var_width[nm] = fw; changed = true; }
                if (fw < 8) var_is_ll[nm] = false;
            }
        }
        /* a store of a float value types the destination pointer `float*`/`double*`.
         * Keep the store's REAL access width (the instruction operand size): a
         * single-precision value packed into an 8-byte `movsd` (`unpcklps` of two
         * floats -> Vector2) must stay an 8-byte store, not shrink to `*(float*)`
         * — otherwise the declared pointer width and the store width disagree. */
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Mem && s.rhs) {
                int fw = float_width_of(s.rhs);
                if (!fw) continue;
                int aw = s.lhs->width ? s.lhs->width : fw;
                s.lhs->is_float = true;
                if (s.lhs->width < fw) s.lhs->width = fw;   /* widen only, never shrink */
                mark_ptr_in_addr(s.lhs->a, aw, false, true);
            }
        }
    }

    bool ret_ptr_elem_float = false;
    /* does a returned pointer expression deref a float* (for `float*` returns)? */
    bool ret_expr_float_ptr(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Var) return ptr_elem_float.count(e->name) && ptr_elem_float[e->name];
        if (e->kind == EK::Cast || e->kind == EK::AddrOf) return ret_expr_float_ptr(e->a);
        if (e->kind == EK::Binary) return ret_expr_float_ptr(e->a) || ret_expr_float_ptr(e->b);
        return false;
    }
    /* A function whose EVERY return value is a void callee's result (`return
     * g();` where g is void) — modulo trivial `0` sentinels on void early-exit
     * paths — is itself void. build_sig_table's linear heuristic can type such a
     * wrapper `int` (quicksort_full → the now-void quicksort_range), which then
     * binds the void result to a returned temp (`t12 = quicksort_range(...);
     * return t12;`) — invalid C. Uses real dataflow (resolved return exprs), so a
     * genuine value return (a `count` load) is never demoted. Runs before
     * simplify_unused_call_temps so the orphaned temp collapses to a bare call. */
    void demote_void_call_returns() {
        if (!used_return || ret_is_float) return;
        std::vector<ExprP> rets;
        for (auto& b : blocks) {
            if (!b.has_ret_value || !b.ret_raw) continue;
            ExprP rr = b.ret_raw;
            if (rr->kind == EK::Var) {
                const std::string nm = rr->name;
                bool found = false;
                for (auto& b2 : blocks)
                    for (auto& s : b2.stmts)
                        if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var &&
                            s.lhs->name == nm && s.rhs) { rets.push_back(s.rhs); found = true; }
                if (!found) rets.push_back(rr);
            } else rets.push_back(rr);
        }
        if (rets.empty()) return;
        bool any_void_call = false;
        for (auto& rr : rets) {
            ExprP v = rr;
            while (v && v->kind == EK::Cast && v->a) v = v->a;   /* peel (int) framing */
            if (v && v->kind == EK::Call && v->ret_kind == 0) { any_void_call = true; continue; }
            if (v && v->kind == EK::Const) continue;             /* void early-exit sentinel */
            return;   /* a real value return -> not void */
        }
        if (!any_void_call) return;
        used_return = false;
        for (auto& b : blocks) {
            b.has_ret_value = false;
            b.ret_value = nullptr;
            b.ret_raw = nullptr;
        }
    }

    void recover_return_type() {
        recover_signedness();   /* always: params/locals of void fns get sign too */
        if (!used_return) return;
        /* Gather the actual returned VALUES. When a function returns a single merged
         * temp (`switch{ case: t=...; } return t;`), the bare `return t` carries no
         * type; resolve the temp to its per-case assignments so the pointer/integer/
         * sign tallies see the real expressions (one `char*` Pearson path must not
         * make the whole hash function `signed char*`). */
        std::vector<ExprP> rets;
        for (auto& b : blocks) {
            if (!b.has_ret_value || !b.ret_raw) continue;
            ExprP rr = b.ret_raw;
            if (rr->kind == EK::Var) {
                const std::string nm = rr->name;
                bool found = false;
                for (auto& b2 : blocks)
                    for (auto& s : b2.stmts)
                        if (s.kind==SK::Assign && s.lhs && s.lhs->kind==EK::Var &&
                            s.lhs->name==nm && s.rhs) { rets.push_back(s.rhs); found = true; }
                if (!found) rets.push_back(rr);
            } else rets.push_back(rr);
        }
        int ew = 0; bool eu = false; bool any_ptr = false; bool fl = false;
        int ptr_rets = 0, int_rets = 0;
        int uns_rets = 0, sgn_rets = 0;
        /* a bit-reinterpret `*(int*)&f` (a movd of a float's bits) is an INTEGER value,
         * not a pointer — its address is an `&` but its VALUE is the int at that address.
         * Without this it counts as neither, leaving int_rets==0 and mis-inferring the whole
         * function as pointer-returning (every `return f` becomes an illegal `(int*)f`). */
        auto is_bit_reinterp = [&](const ExprP& x) -> bool {
            ExprP m = x; while (m && m->kind == EK::Cast) m = m->a;
            return m && m->kind == EK::Mem && m->a && m->a->kind == EK::AddrOf && !m->is_float;
        };
        for (auto& rr : rets) {
            int e2 = 0; bool u2 = false;
            if (expr_is_pointer(rr, &e2, &u2) && !is_bit_reinterp(rr)) {
                any_ptr = true; ++ptr_rets;
                if (e2 && !ew) { ew = e2; eu = u2; }
                if (ret_expr_float_ptr(rr)) fl = true;
            } else if (expr_clearly_integer(rr) || is_bit_reinterp(rr)) {
                ++int_rets;
            }
            /* return signedness: a value computed by unsigned ops (logical >>,
             * unsigned / %, unsigned casts/loads) is `unsigned`. Tally per path. */
            /* UNSIGNED uses variable signedness (a returned `crc` var is unsigned from
             * its logical-shift history). SIGNED requires a strong signed OPERATION in
             * the return expression itself (sar / signed div / a `(signed char)` movsx
             * read) — a signed VARIABLE alone (`return len*2`) doesn't count, since it
             * is merely converted to the return type. */
            if (expr_signedness(rr) > 0) ++uns_rets;
            if (ret_has_strong_signed_op(rr)) ++sgn_rets;
        }
        /* Unsigned return: at least one path is genuinely unsigned and NONE is
         * genuinely signed. `sgn_rets` now counts only STRONG signed evidence (sar,
         * signed div, a movsx `(signed char)`/`(short)` read, a var proven signed) —
         * NOT width-framing casts or signed params through agnostic ops — so a hash
         * suite (all logical shifts) stays unsigned while a codec (movsx i-reads +
         * idiv) is correctly signed. */
        if (uns_rets > 0 && sgn_rets == 0) ret_is_unsigned = true;

        /* MIXED return: some paths return a float (ret_is_float, in xmm0) and others
         * a pointer (in rax). One C return type cannot hold both register classes,
         * so `return ptr` from a `double` function is C2440. Declare the raw `long
         * long`: both `return <ptr>` and `return <floatexpr>` then compile as
         * conversions (fn_00031b50 returns either a node pointer or a float score). */
        if (ret_is_float && any_ptr) ret_conflict_raw = true;

        /* Byte/short return: the ABI returns an int8/int16 in eax framed as an int
         * `(int)(char)x`, so a uint8_t/int16_t function comes out `unsigned int`.
         * When EVERY return path is such a narrow-cast value (a `(signed char)` /
         * `(unsigned short)` truncation, peeling any outer int/long framing cast),
         * recover the narrow type — reverse_bits8/sum8/crc8 -> `unsigned char`.
         * Reached only through an explicit truncation cast (not a bare byte load or
         * const), so `int f(){ return buf[i]; }` is never wrongly narrowed. */
        if (!any_ptr && !fl && !ret_is_float && !rets.empty()) {
            std::function<int(const ExprP&, bool&)> narrow_w =
                [&](const ExprP& e, bool& uns) -> int {
                    if (!e || e->kind != EK::Cast) return 0;
                    if (e->width == 1 || e->width == 2) { uns = e->is_unsigned; return e->width; }
                    if (e->width >= 4) return narrow_w(e->a, uns);   /* peel int framing */
                    return 0;
                };
            int sw = 0; bool su = false; bool ok = true; bool saw_cast = false;
            std::vector<int64_t> consts;
            for (auto& rr : rets) {
                bool u2 = false; int w2 = narrow_w(rr, u2);
                if (w2) {
                    saw_cast = true;
                    if (sw == 0) { sw = w2; su = u2; }
                    else if (w2 != sw) { sw = std::max(sw, w2); su = su && u2; }
                } else {
                    /* a bare constant path (a null-guard `return 0`) rides along a
                     * narrow return as long as it fits the recovered width. */
                    ExprP c = rr; while (c && c->kind == EK::Cast && c->a) c = c->a;
                    if (c && c->kind == EK::Const) consts.push_back(c->cval);
                    else { ok = false; break; }
                }
            }
            if (ok && saw_cast && (sw == 1 || sw == 2)) {
                int64_t lo = sw == 1 ? (su ? 0 : -128) : (su ? 0 : -32768);
                int64_t hi = sw == 1 ? (su ? 255 : 127) : (su ? 65535 : 32767);
                for (int64_t cv : consts) if (cv < lo || cv > hi) { ok = false; break; }
            }
            if (ok && saw_cast && (sw == 1 || sw == 2)) {
                ret_small_w = sw; ret_small_uns = su; ret_width = sw;
                for (auto& b : blocks) {
                    if (!b.has_ret_value || !b.ret_raw) continue;
                    ExprP r = clone(b.ret_raw);
                    while (r && r->kind == EK::Cast && r->width >= 4 && r->a) r = r->a;
                    if (!(r && r->kind == EK::Cast && r->width == sw))
                        r = mkCast(cast_str(sw, su), r, sw, su);
                    b.ret_value = fold(r);
                }
                return;   /* narrow return settled; pointer/int tally is moot */
            }
        }

        /* A function is pointer-returning only when NO path returns a clearly-integer
         * value: one `char*` path (a Pearson table walker) among 16 integer-hash
         * returns is an integer function, not a `signed char*` one. A path that returns a
         * FLOAT (in xmm0) makes it a mixed float/ptr fn — handled as `long long` by
         * ret_conflict_raw above, NOT a pointer (else `return f` becomes an illegal `(T*)f`). */
        if (!any_ptr || int_rets > 0 || ret_is_float) return;
        ret_is_pointer = true;
        ret_ptr_elem_w = ew;
        ret_ptr_elem_uns = eu;
        ret_ptr_elem_float = fl;
        ret_width = 8;
        /* NOTE: the struct-pointer return type is NOT decided here — param_structs is still
         * empty at this point in the pipeline (recover_struct_layouts runs later). See
         * recover_return_struct_type(), called right after the layouts exist. */
        /* rebuild ret_value from the untruncated raw expression */
        for (auto& b : blocks) {
            if (b.has_ret_value && b.ret_raw) b.ret_value = clone(b.ret_raw);
        }
    }

    /* A return expression that is plainly an integer computation (arithmetic / a
     * cast to an integer type), NOT a pointer and NOT a bare const sentinel. Used to
     * stop one stray pointer-typed path from making the whole function pointer-typed. */
    bool expr_clearly_integer(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Binary) {
            const std::string& o = e->op;
            return o=="+"||o=="-"||o=="*"||o=="/"||o=="%"||o=="<<"||o==">>"||
                   o=="&"||o=="|"||o=="^"||o=="mulh"||o=="umulh";
        }
        if (e->kind == EK::Cast) {
            return e->op.find("char*") == std::string::npos &&
                   e->op.find("*") == std::string::npos;
        }
        return false;
    }

    /* True if the expression performs a STRONG signed OPERATION: an arithmetic `>>`
     * (sar), a signed `/`/`%` (idiv), or a `(signed char)`/`(short)` movsx read. These
     * are sign-revealing operations, unlike a signed variable merely converted to the
     * return type. Used so a hash suite (all logical shifts) stays unsigned while a
     * codec with a real `idiv`/`sar`/movsx return is correctly signed. */
    bool ret_has_strong_signed_op(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Binary) {
            const std::string& o = e->op;
            if ((o==">>"||o=="/"||o=="%") && !e->is_unsigned) return true;
        }
        if (e->kind == EK::Cast &&
            (e->op.find("(signed char)") != std::string::npos ||
             e->op.find("(short)") != std::string::npos))
            return true;
        return ret_has_strong_signed_op(e->a) || ret_has_strong_signed_op(e->b) ||
               ret_has_strong_signed_op(e->c);
    }

    /* Signedness of a value: +1 unsigned, -1 signed, 0 unknown. C's "unsigned is
     * contagious" rule: a mixed arithmetic expression is unsigned if any operand is.
     * Strong signals: logical `>>` / unsigned `/ %` (is_unsigned set by SHR/DIV) =>
     * unsigned; arithmetic `>>` / signed `/ %` => signed; an `(unsigned ...)` cast =>
     * unsigned. Variables consult var_unsigned (filled by propagate_signedness). */
    int expr_signedness(const ExprP& e) {
        if (!e) return 0;
        switch (e->kind) {
            case EK::Cast: {
                const std::string& c = e->op;
                if (c.find("unsigned") != std::string::npos) return 1;   /* unsigned conv */
                /* a NARROWING signed cast (`(signed char)`/`(short)`) is the movsx
                 * sign-extension idiom — strong evidence the value is signed. A WIDE
                 * cast (`(int)`/`(long long)`) is usually return/width framing that
                 * wraps a value of either sign, so recurse to the inner value. */
                if (c.find("(signed char)") != std::string::npos ||
                    c.find("(short)") != std::string::npos)
                    return -1;
                int inner = expr_signedness(e->a);
                return inner ? inner : 0;
            }
            case EK::Mem:
                return e->is_unsigned ? 1 : 0;
            case EK::Var: {
                auto it = var_unsigned.find(e->name);
                if (it != var_unsigned.end()) return it->second ? 1 : -1;
                return 0;
            }
            case EK::Const:
                if (e->is_unsigned) return 1;
                /* a 32-bit literal above INT_MAX is `unsigned int` in C (`0xfffffc80`),
                 * so `x & C` / `x | C` is unsigned — a real signedness signal for the
                 * C4018 relational fix. */
                if (e->width && e->width <= 4 &&
                    (unsigned long long)e->cval > 0x7fffffffULL &&
                    (unsigned long long)e->cval <= 0xffffffffULL) return 1;
                return 0;   /* otherwise a literal carries no decisive signedness */
            case EK::Binary: {
                const std::string& o = e->op;
                if (o==">>"||o=="/"||o=="%") return e->is_unsigned ? 1 : -1;
                if (o=="<"||o=="<="||o==">"||o==">="||o=="=="||o=="!="||
                    o=="&&"||o=="||") return 0;   /* boolean result */
                if (o=="umulh") return 1;
                if (o=="mulh")  return -1;
                /* +,-,*,&,|,^,<<: contagion — unsigned if either side is */
                int sa = expr_signedness(e->a), sb = expr_signedness(e->b);
                if (sa > 0 || sb > 0) return 1;
                if (sa < 0 || sb < 0) return -1;
                return 0;
            }
            case EK::Unary:
                return expr_signedness(e->a);
            default:
                return 0;
        }
    }

    /* Per-variable signedness recovery — a FLAGSHIP correctness goal: recover the
     * declared sign of every integer parameter, local and return value. Two evidence
     * sources, both behavior-safe (the rendered output already casts each operation,
     * so a variable's declared sign affects only the recovered TYPE, never the
     * computed value):
     *   (1) USE CONTEXT — a var consumed by a logical `>>`, an unsigned `/`/`%`, or
     *       an unsigned compare (`ja/jb`) is unsigned; by an arithmetic `>>` (sar),
     *       a signed `/`, or a signed compare (`jg/jl`) is signed. Votes are tallied.
     *   (2) DEFINITION — a temp assigned a value that is itself unsigned (a movzx
     *       zero-extend, an unsigned op) is unsigned; propagated to a fixpoint so
     *       temp->temp chains resolve. Definition evidence (precise) wins over the
     *       use votes (which a value used both ways can split).
     * Parameters have no definition, so their sign comes from use votes alone. */
    void collect_sign_votes(const ExprP& e) {
        if (!e) return;
        if (e->kind == EK::Binary) {
            const std::string& o = e->op;
            int s = e->is_unsigned ? +1 : -1;
            auto vote = [&](const ExprP& x){ if (x && x->kind==EK::Var) sign_votes[x->name] += s; };
            /* Only the STRONG signals vote: a logical-vs-arithmetic `>>` (shr/sar) and
             * an unsigned-vs-signed `/`/`%` (div/idiv) directly reflect the operand's
             * declared sign. COMPARES do NOT vote: MSVC emits an unsigned `cmp;ja` for
             * switch/range bounds even on signed values (`(unsigned)algo > 16`), which
             * would falsely mark a signed selector unsigned. */
            if (o == ">>") vote(e->a);                                 /* shifted value */
            else if (o=="/"||o=="%") { vote(e->a); vote(e->b); }
            /* A SIGNED ordered compare against 0 (`x < 0` / `x >= 0`, from jl/jge/
             * js/jns) is authoritative: an unsigned value is never < 0, so the
             * compiler would never emit a signed compare-to-zero on it. This is the
             * `if (x < 0)` sign-test idiom (my_itoa's negative-number handling) and
             * must override the copy-taint from an unsigned sibling (e.g. the abs
             * value `v = x` then `v / 10` unsigned). Unlike general compares (which
             * do NOT vote), the operand-vs-ZERO signed test cannot be an unsigned
             * range-check trick. */
            else if ((o=="<"||o=="<="||o==">"||o==">=") && !e->is_unsigned) {
                if (e->b && e->b->kind==EK::Const && e->b->cval==0 && e->a && e->a->kind==EK::Var)
                    zero_signed_vars.insert(e->a->name);
                else if (e->a && e->a->kind==EK::Const && e->a->cval==0 && e->b && e->b->kind==EK::Var)
                    zero_signed_vars.insert(e->b->name);
            }
        }
        collect_sign_votes(e->a); collect_sign_votes(e->b); collect_sign_votes(e->c);
        for (auto& ar : e->args) collect_sign_votes(ar);
    }

    void recover_signedness() {
        sign_votes.clear();
        zero_signed_vars.clear();
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { collect_sign_votes(s.lhs); collect_sign_votes(s.rhs); }
            collect_sign_votes(b.cond);
            collect_sign_votes(b.ret_raw);
            collect_sign_votes(b.ret_value);
            collect_sign_votes(b.switch_var);
            if (b.tail_call) collect_sign_votes(b.tail_call);
        }
        /* seed from use votes (the only evidence for parameters) */
        for (auto& kv : sign_votes) {
            if (kv.second > 0) var_unsigned[kv.first] = true;
            else if (kv.second < 0) var_unsigned[kv.first] = false;
        }
        /* definition-based propagation overrides votes for assigned temps/locals */
        for (int pass = 0; pass < 5; ++pass) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            bool changed = false;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) {
                    if (s.kind != SK::Assign || !s.lhs || !s.rhs) continue;
                    if (s.lhs->kind != EK::Var) continue;
                    int sg = expr_signedness(s.rhs);
                    if (sg != 0) {
                        bool u = (sg > 0);
                        auto it = var_unsigned.find(s.lhs->name);
                        if (it == var_unsigned.end() || it->second != u) {
                            var_unsigned[s.lhs->name] = u; changed = true;
                        }
                    }
                    /* A pure copy `t = src` (Var=Var) carries the SAME value, so an
                     * unsigned use of either side implies the other is unsigned too.
                     * Back-propagate so a `seed` copied then logical-shifted (the /O2
                     * `mov rX,seed; shr rX,32` form) recovers the unsigned parameter. */
                    if (s.rhs->kind == EK::Var) {
                        bool lu = var_unsigned.count(s.lhs->name) && var_unsigned[s.lhs->name];
                        bool ru = var_unsigned.count(s.rhs->name) && var_unsigned[s.rhs->name];
                        if (lu && !ru) { var_unsigned[s.rhs->name] = true; changed = true; }
                        else if (ru && !lu) { var_unsigned[s.lhs->name] = true; changed = true; }
                    }
                }
            }
            if (!changed) break;
        }
        /* Authoritative override: a var sign-tested against 0 (`x < 0`/`x >= 0`) is
         * signed, no matter what copy/def propagation concluded from an unsigned
         * sibling. Applied last so it wins. */
        for (auto& n : zero_signed_vars) var_unsigned[n] = false;
    }
    std::map<std::string,int> sign_votes;
    std::set<std::string> zero_signed_vars;   /* proven signed by `x</>=0` sign-test */
    void scan_types(const ExprP& e, bool is_lhs) {
        if (!e) return;
        if (e->kind == EK::Mem) mark_ptr_in_addr(e->a, e->width ? e->width : 1, e->is_unsigned, e->is_float);
        if (e->kind == EK::Var) {
            int w = e->width ? e->width : 4;
            auto it = var_width.find(e->name);
            if (it == var_width.end() || w > it->second) var_width[e->name] = w;
        }
        scan_types(e->a, false); scan_types(e->b, false); scan_types(e->c, false);
        for (auto& ar : e->args) scan_types(ar, false);
        (void)is_lhs;
    }
    void mark_ptr_in_addr(const ExprP& e, int elem_w = 0, bool elem_uns = false,
                          bool elem_float = false, bool stride_match = false) {
        if (!e) return;
        /* `*(T*)&x` (a bit-reinterpret, e.g. movd of a float's bits) has an AddrOf address:
         * the inner `x` is a VALUE being reinterpreted, NOT a pointer. Do not descend past
         * the `&` — else a float local `f` in `*(int*)&f` is mis-typed `int*` (C2111/C2440
         * in sinf/cosf Taylor code). Same for the offset form `*(int*)((char*)&s + off)`. */
        if (e->kind == EK::AddrOf) return;
        if (e->kind == EK::Var) {
            /* stack-array locals keep their `char buf[N]` declaration; do not
             * retype them as pointers (the byte-addressed (T*) casts stay). */
            if (array_locals.count(e->name)) return;
            var_pointer[e->name] = true; var_is_ll[e->name] = true;
            /* Element width from the deref. The ARRAY STRIDE is authoritative: an
             * access `*(T*)(p + i*sizeof(T))` whose index scale EQUALS the access
             * width is genuine array iteration and reveals the element type. A
             * const-offset wide store (a merged memset: int[16] zeroed via qword
             * stores) or a sub-field read (the low 4 bytes of a long long) has
             * scale != width and is weaker evidence. Rules: a stride-matched width
             * beats a non-stride-matched one; among equals, the LARGER wins (a
             * sub-field read never widens a real element). Fixes BOTH int[16]-as-
             * long long[8] (histogram: int stride-4 beats qword const-offset) AND
             * long long*-as-int* (regs: qword stride-8 beats int sub-field reads). */
            if (elem_w > 0) {
                auto it = ptr_elem_width.find(e->name);
                bool was_auth = ptr_elem_authoritative.count(e->name) != 0;
                if (it == ptr_elem_width.end()) {
                    ptr_elem_width[e->name] = elem_w; ptr_elem_uns[e->name] = elem_uns;
                    if (stride_match) ptr_elem_authoritative.insert(e->name);
                } else if (stride_match && !was_auth) {
                    it->second = elem_w; ptr_elem_uns[e->name] = elem_uns;
                    ptr_elem_authoritative.insert(e->name);
                } else if (stride_match == was_auth) {
                    /* same authority class: a wider element wins (sub-field reads
                     * and partial merged stores are both narrower than the real). */
                    if (elem_w > it->second) { it->second = elem_w; ptr_elem_uns[e->name] = elem_uns; }
                }
                /* (!stride_match && was_auth): never let a non-stride access
                 * override an authoritative array stride. */
            }
            /* a deref proven float (movss/scalar-FP) types the pointer float*. */
            if (elem_float) {
                ptr_elem_float[e->name] = true;
                /* float element width is MIN-wins (single beats double): a `movss`
                 * (4B) store/load proves a single-precision element; a sibling `movsd`
                 * (8B) is a PACKED 2-float (Vector2) store, not a double. Without this
                 * a float[] written `movss [p];movss [p+4]; movsd [p]` (unpcklps pack)
                 * typed `double*` from the 8B max-wins width (fun_0000d1f0/0x11080). */
                if (elem_w > 0) {
                    auto it = ptr_elem_float_w.find(e->name);
                    if (it == ptr_elem_float_w.end() || elem_w < it->second)
                        ptr_elem_float_w[e->name] = elem_w;
                }
            }
            /* ...but a NON-float qword deref through the same pointer proves it is a
             * heterogeneous STRUCT base (its first field a pointer/handle), not a
             * float array — a real float[]/double[] never holds a qword scalar. Record
             * it so the float typing is suppressed later (the per-field `*(float*)`
             * casts still render the float members; the bare `*p` then derefs the
             * qword correctly instead of being mistyped `*(double*)`). */
            if (!elem_float && elem_w >= 8) ptr_nonfloat_qword.insert(e->name);
            return;
        }
        /* For `base + index*scale`, only the additive base is the pointer; a
         * scaled term (index * const) is the array index, not a pointer. This
         * keeps the index variable a plain integer rather than mistyping it as
         * `long long*`, and lets the array-subscript renderer find the base. */
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-")) {
            auto is_scaled = [](const ExprP& x) {
                return x && x->kind == EK::Binary && x->op == "*";
            };
            auto scale_of = [](const ExprP& x) -> int {
                if (x && x->kind == EK::Binary && x->op == "*") {
                    if (x->b && x->b->kind == EK::Const) return (int)x->b->cval;
                    if (x->a && x->a->kind == EK::Const) return (int)x->a->cval;
                }
                return 0;
            };
            if (is_scaled(e->a) && !is_scaled(e->b)) { mark_ptr_in_addr(e->b, elem_w, elem_uns, elem_float, scale_of(e->a) == elem_w); return; }
            if (is_scaled(e->b) && !is_scaled(e->a)) { mark_ptr_in_addr(e->a, elem_w, elem_uns, elem_float, scale_of(e->b) == elem_w); return; }
            /* additive index (esize==1 char arrays): base + index. Mark whichever
             * side is a Var as the pointer base, the other stays an integer. */
            if (e->a && e->a->kind == EK::Var && e->b && e->b->kind != EK::Var) {
                mark_ptr_in_addr(e->a, elem_w, elem_uns, elem_float, elem_w == 1); return;
            }
            if (e->b && e->b->kind == EK::Var && e->a && e->a->kind != EK::Var) {
                mark_ptr_in_addr(e->b, elem_w, elem_uns, elem_float, elem_w == 1); return;
            }
        }
        mark_ptr_in_addr(e->a, elem_w, elem_uns, elem_float, stride_match);
        mark_ptr_in_addr(e->b, elem_w, elem_uns, elem_float, stride_match);
    }
    std::map<std::string,int>  ptr_elem_width;   /* pointer var -> element byte width */
    std::map<std::string,bool> ptr_elem_uns;     /* pointer var -> element unsigned? */
    std::map<std::string,bool> ptr_elem_float;   /* pointer var -> element is float */
    std::map<std::string,int>  ptr_elem_float_w; /* float pointer -> element width (MIN-wins: single beats packed) */
    std::set<std::string>      ptr_nonfloat_qword;  /* pointer also deref'd as a non-float qword => struct base, not float[] */
    std::set<std::string>      ptr_elem_authoritative;  /* width came from an array stride (scale==width) */

    void finalize_params() {
        int max_home = 0;
        for (auto& kv : param_home_off) {
            const std::string& nm = kv.second;
            if (nm.size() >= 2 && nm[0]=='a') {
                int idx = atoi(nm.c_str() + 1);
                if (idx > max_home) max_home = idx;
            }
        }
        /* If parameters were homed in the prologue / read off the stack (the
         * reliable /Od signals, incl. args 5+), trust exactly that count.
         * Otherwise use the sig-table estimate. */
        /* float params live in XMM by position and are never homed to a stack
         * slot, so they don't appear in param_home_off — fold their highest
         * position in so int-home detection doesn't truncate the count. */
        int fmax = 0;
        for (int p = 0; p < 4; ++p) if (is_float_param[p]) fmax = p + 1;
        /* reg_param_max recovers un-homed GPR args (release builds). It already
         * includes the homed positions, so it dominates max_home when args are
         * read straight from registers. */
        int gmax = std::max(max_home, reg_param_max);
        if (gmax > 0) {
            num_params = std::max(gmax, fmax);
        } else if (sigtab && sigtab->count(f->rva)) {
            num_params = std::max(num_params, sigtab->at(f->rva).param_count);
        }
        num_params = std::max(num_params, std::max(fmax, reg_param_max));

        /* UNHOMED release frames read args straight from registers; the linear
         * detect_reg_params can still under-count an argument first used only on a
         * later CFG path (it is a flat instruction walk). That drops a real pointer
         * parameter and collapses every [rdx+off]/[r8+off]/[r9+off] dereference to
         * `(char*)0` — the dominant null-base family (0x5cf90's 58, 0x7a628, ...).
         * Recover it with PRECISE entry-block liveness over genuine operand reads
         * (compute_reg_liveness(false) excludes the synthetic call-arg uses, so an
         * indirect call's pc=4 cannot invent phantom params). MS x64 args are
         * positional: the highest live-in slot implies every lower slot is a param.
         * This runs for HOMED frames too — a /Od home store `mov [rsp+8],rcx`
         * genuinely READS its arg reg, so genuine-read liveness reproduces the
         * homed count exactly (corpus 484/0 unaffected) — while ALSO recovering a
         * PARTIALLY-homed release frame that homes rcx but reads rdx straight from
         * the register (0x5cf90: r8=rdx dereferenced as the output struct). The
         * call-arg-use exclusion (false) is what keeps an indirect call from
         * inventing phantom params; the old coarse `!homed` whole-function skip is
         * no longer needed and missed exactly these partially-homed frames. */
        bool homed = param_used[0]||param_used[1]||param_used[2]||param_used[3];
        (void)homed;
        /* Run entry-liveness even on HOMED frames: a /O2 frame that homes rcx/rdx
         * to the shadow space but keeps r8/r9 in registers (match_here/word_wrap's
         * 4th arg) was missing the register-only param -> an `in_R9` leak and wrong
         * recursive-call args. /Od homes ALL params, so the homing-store reads make
         * live_max == the homed count (corpus unaffected). Only EXTENDS num_params. */
        if (e->arch == DS_ARCH_X64 && !blocks.empty()) {
            compute_reg_liveness(false);
            int eb = entry_block();
            if (eb >= 0 && eb < (int)reg_live_in.size()) {
                static const Reg ga[4] = { R_RCX, R_RDX, R_R8, R_R9 };
                /* GPR arg slots ONLY. XMM is intentionally excluded: float corpus
                 * routines use xmm0-3 as cross-block accumulators (read-before-
                 * write spanning blocks), so an xmm-liveness probe invents phantom
                 * float params and shattered the corpus (484->325). Genuine float
                 * params are recovered separately by detect_float_params (fmax). */
                int live_max = 0;
                for (int p = 0; p < 4; ++p)
                    if (reg_live_in[eb][ga[p]]) live_max = p + 1;
                num_params = std::max(num_params, live_max);
            }
        }
        if (num_params > 32) num_params = 32;
        if (num_params < 0) num_params = 0;

        /* return kind from sig table */
        if (sigtab && sigtab->count(f->rva)) {
            const FuncSig& s = sigtab->at(f->rva);
            int rk = s.ret_kind;
            if (rk == 0) { used_return = false; }
            else if (rk == 3 || rk == 4) {           /* float / double in xmm0 */
                used_return = true; ret_is_float = true;
                ret_width = (rk == 4) ? 8 : 4;
            } else { used_return = true; ret_width = (rk == 2) ? 8 : 4; }
            if (s.ret_byte && used_return && !ret_is_float) {
                ret_byte_return = true; ret_width = 1;   /* bool/char in al */
            }
        }
    }

    /* +1 if the condition is a compile-time TRUE, -1 if compile-time FALSE, 0 if
     * it depends on runtime data. fold() deliberately leaves `0 == 0` and friends
     * un-collapsed, so the literal-vs-literal comparison is evaluated here. */
    int const_cond(const ExprP& c) {
        if (!c) return 0;
        if (c->kind == EK::Const) return c->cval != 0 ? 1 : -1;
        if (c->kind == EK::Binary && c->a && c->b &&
            c->a->kind == EK::Const && c->b->kind == EK::Const) {
            int64_t x = c->a->cval, y = c->b->cval; bool r;
            const std::string& op = c->op;
            if (op == "==")      r = (x == y);
            else if (op == "!=") r = (x != y);
            else if (op == "<")  r = (x <  y);
            else if (op == ">")  r = (x >  y);
            else if (op == "<=") r = (x <= y);
            else if (op == ">=") r = (x >= y);
            else return 0;
            return r ? 1 : -1;
        }
        return 0;
    }

    /* Constant-condition / dead-branch peephole. A conditional block whose
     * condition folded to a compile-time constant (`if (1)`, `if (0 == 0)`,
     * `if (1 == 0)`, `if (0 != 0)`) is rewritten to an UNCONDITIONAL jump to its
     * single live successor, severing the dead edge. Behavior-preserving — the
     * constant already decided the branch in the emitted code — and it erases the
     * entire `if (<const>)` artifact class. Dominators/loops are recomputed since
     * the CFG changed. (Genuine lost conditions are NOT dropped here: cmpxchg/cpuid
     * are modeled into real conditions upstream, so only true constants reach
     * this pass.) */
    void simplify_const_branches() {
        bool changed = false;
        for (auto& b : blocks) {
            if (!b.ends_jcc || b.taken < 0 || b.fall < 0) continue;
            int cc = const_cond(b.cond);
            if (cc == 0) continue;
            int keep = (cc > 0) ? b.taken : b.fall;
            int drop = (cc > 0) ? b.fall : b.taken;
            if (drop != keep && drop >= 0 && drop < (int)blocks.size()) {
                auto& dp = blocks[drop].pred;
                dp.erase(std::remove(dp.begin(), dp.end(), b.id), dp.end());
            }
            b.ends_jcc = false; b.cc = CC::NONE; b.cond = nullptr;
            b.ends_jmp = true; b.taken = keep; b.fall = -1;
            b.succ.clear(); if (keep >= 0) b.succ.push_back(keep);
            changed = true;
        }
        if (changed) { compute_dominators(); compute_postdom(); find_loops(); }
    }

    /* =================================================================== */
    /*  Top-level driver                                                    */
    /* =================================================================== */

    std::string run() {
        if (!disassemble()) return stub("/* decompilation failed: disasm */");
        self_fname = (f && f->name[0]) ? sani(std::string(f->name))
                                       : "sub_" + hex(f->rva).substr(2);
        /* TEMP phase profiler (DS_PHASE_TIMING) — pinpoints the hot pass in a slow
         * function so the per-function time budget can guard it. */
        auto _ph_t0 = std::chrono::steady_clock::now();
        auto _ph_last = _ph_t0;
        const bool _ph_dbg = std::getenv("DS_PHASE_TIMING") != nullptr;
        /* DS_PASS_TRACE — DETERMINISTIC per-pass fingerprint (no timings). Run the
         * same binary twice, diff the two logs, and the FIRST differing line names
         * the pass that introduced a run-to-run difference. Built for hunting
         * nondeterminism (pointer-ordered iteration reorders temp minting), which
         * is invisible to the timing profiler. */
        const bool _ph_trace = std::getenv("DS_PASS_TRACE") != nullptr;
        auto _phase = [&](const char* nm) {
            if (_ph_trace) {
                uint64_t h = 1469598103934665603ull;
                size_t nstmt = 0;
                /* Structural hash of the whole expression forest — NO pointers, so
                 * it is comparable across processes. */
                std::function<void(const ExprP&)> hx = [&](const ExprP& e) {
                    if (!e) { h ^= 0x9ull; h *= 1099511628211ull; return; }
                    auto mix = [&](uint64_t v){ h ^= v + 0x9e3779b97f4a7c15ull; h *= 1099511628211ull; };
                    mix((uint64_t)e->kind); mix((uint64_t)e->width);
                    mix((uint64_t)e->cval); mix(e->is_float ? 1 : 2);
                    for (char c : e->op)     mix((uint64_t)(unsigned char)c);
                    for (char c : e->name)   mix((uint64_t)(unsigned char)c);
                    for (char c : e->callee) mix((uint64_t)(unsigned char)c);
                    hx(e->a); hx(e->b); hx(e->c);
                    for (auto& a : e->args) hx(a);
                };
                for (auto& b : blocks) {
                    nstmt += b.stmts.size();
                    for (auto& s : b.stmts) {
                        h ^= (uint64_t)s.kind + 0x9e3779b9u; h *= 1099511628211ull;
                        h ^= (uint64_t)s.addr;               h *= 1099511628211ull;
                        hx(s.lhs); hx(s.rhs);
                    }
                    hx(b.cond); hx(b.ret_value); hx(b.switch_var); hx(b.tail_call);
                }
                fprintf(stderr, "TRACE %-24s rva=%llx temp_seq=%d blocks=%zu stmts=%zu h=%016llx\n",
                        nm, (unsigned long long)(f ? f->rva : 0), temp_seq,
                        blocks.size(), nstmt, (unsigned long long)h);
            }
            if (!_ph_dbg) return;
            auto n = std::chrono::steady_clock::now();
            fprintf(stderr, "PHASE %-22s %7lld ms   (cum %7lld)\n", nm,
                    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(n - _ph_last).count(),
                    (long long)std::chrono::duration_cast<std::chrono::milliseconds>(n - _ph_t0).count());
            _ph_last = n;
        };
        if (std::getenv("DS_DBG_DISASM")) {
            fprintf(stderr, "==== DISASM @ 0x%llx (%zu insns) ====\n",
                    (unsigned long long)(f ? f->rva : 0), insns.size());
            for (auto& in : insns)
                fprintf(stderr, "  %llx: %-8s %s\n",
                        (unsigned long long)in.addr, in.mnem.c_str(), in.ops.c_str());
        }
        /* Arm the per-function deadline now that the instruction list exists (the
         * cap scales with function size). Everything above this point is linear. */
        budget_init();
        scan_prologue();
        detect_param_homes();
        scan_addressed_stack();
        scan_callee_saves();
        scan_cookie_calls();
        detect_reg_params();
        detect_stack_params();
        detect_cdecl_params();
        detect_float_params();
        build_cfg();
        if (blocks.empty()) return stub("/* decompilation failed: no blocks */");
        if (!std::getenv("DS_NO_FPCOLLAPSE")) collapse_fp_parity_branches();

        finalize_params();
        detect_reused_param_homes();
        init_entry_regs();

        compute_dominators();
        compute_postdom();
        find_loops();

        /* Cross-block register dataflow: propagate every live register's value
         * through the whole CFG to a fixpoint (single-pred chains included),
         * materializing phi-temps at real merges. Replaces the old single-pass
         * merge-only pass that collapsed carried register values to `0`. The
         * final iteration's exec leaves reg_out/stmts consistent; then inject the
         * phi assignments into predecessors (after the last clear, so they live). */
        _phase("pre-fixpoint");
        compute_call_before_block();   /* before exec: reaching_argc gates on it */
        compute_entry_regs_fixpoint();
        _phase("fixpoint");
        inject_phis();

        local_dead_store_elim();
        dead_store_elim();
        _phase("  dse1");
        copy_propagate();
        _phase("  copy_propagate1");
        local_dead_store_elim();
        dead_store_elim();
        global_dead_store_elim();
        _phase("  dse2+global");
        trim_phantom_call_args();
        trim_format_args();   /* a format string states a variadic call's real arity */
        demote_void_call_returns();
        simplify_unused_call_temps();
        canonicalize_branch_after_assign();
        _phase("  trims");
        collect_var_info();
        _phase("  collect_var_info");
        propagate_pointer_types();
        propagate_float_types();
        _phase("  propagate_types");
        /* A pointer deref'd as a non-float qword somewhere is a struct base, not a
         * float array: drop the float typing so it declares `long long*` (the per-
         * field `*(float*)` casts still render the float members correctly). */
        for (const auto& n : ptr_nonfloat_qword) ptr_elem_float.erase(n);
        /* AFTER both pointer- and float-type inference are settled: a var declared a
         * pointer but assigned a float value is a mis-merged register -> raw. */
        mark_type_conflict_raw();
        recover_return_type();
        simplify_const_branches();   /* erase `if (<const>)` artifacts (DCE) */
        recognize_magic_div();       /* __mulh(x,M)>>s idiom -> x / C  (round-trip verified;
                                      * runs AFTER naming/typing, BEFORE cse re-splits) */
        _phase("  pre-cse");
        cse_materialize();           /* hoist repeated subexprs into named temps */
        _phase("  cse_materialize");
        cse_cross_statement();       /* hoist loop-invariant address arithmetic */
        _phase("  cse_cross_statement");
        cse_global();                /* multi-use pure values -> one temp (strict-dom only) */
        _phase("  cse_global");
        /* copy_propagate ran BEFORE cse, so the single-use copy chains cse leaves
         * behind (`t453 = t463; use t453` — register-move temps that only became
         * dead once cse hoisted their shared source) were never cleaned. Re-run it:
         * cse temps have >=2 uses so they are never un-hoisted; only these residual
         * one-use copies collapse, cutting the `tN = tM; tM2 = tM` cascades. */
        copy_propagate();
        _phase("cse+propagate");
        demote_comparison_temps();   /* bool-in-float-temp -> int (AFTER cse extracts the
                                      * ternary condition `t7 = 0.0f > t6` into a temp) */
        rescue_const_float_vars();   /* all-const-def slot used in scalar-FP arith -> float
                                      * (a float .rdata const that lost is_float via a phi) */
        float_bits_store_by_alias(); /* int-const store aliasing a float access -> float store
                                      * (`mov dword[p+0x1c],0xBF800000` beside `movss [p+0x1c]`) */
        retype_float_constants();    /* `float t=0x40800000` -> `4.0f` (lost-is_float .rdata const) */
        promote_leaked_arg_params(); /* `in_RCX`/`in_XMM2` -> the parameter a1/a3 it IS */
        /* Re-run the use-as-pointer inference NOW that CSE/materialization (above) has
         * minted its temps: the pointer-type pass at ~11172 ran BEFORE cse_materialize,
         * so a hoisted `tN = qword_glob + off` (or `tN = *(long long*)..`) that is later
         * DEREFERENCED (`*(float*)tN`, `*(float*)((char*)tN+K)`) was left `long long`,
         * forcing an int->pointer conversion at every use (roadmap #1, the long-long-
         * global base case the first pass' ptr_value_of can't see). collect_var_info's
         * mark_ptr_in_addr re-scans the derefs and types tN a pointer; the RHS then
         * gets the `(T*)` assignment cast. Purely additive (only deref'd temps become
         * pointers), and the mark_type_conflict_raw below cleans up any new float/ptr
         * clash. */
        mark_late_deref_pointers();
        propagate_pointer_types();
        for (const auto& n : ptr_nonfloat_qword) ptr_elem_float.erase(n);
        /* Re-run conflict detection AFTER param promotion: a mis-typed float/double
         * param arrives as a leaked `in_XMMn` register at the first pass (so the
         * PARAM rules, keyed on `a1`..`aN`, could not see it) and only becomes `a4`
         * here. The pass is idempotent (clears + recomputes), so the second run just
         * refines with the final names (`t2 = a4` now recognizes a4). */
        mark_type_conflict_raw();

        /* AFTER the pointer/float inference, NOT before it. This reads var_pointer /
         * ptr_elem_width to refuse overriding a proven pointer, and at its first (natural-
         * looking) home right after trim_format_args those maps do not exist yet:
         * collect_var_info + propagate_pointer_types run ~5 lines LATER. An empty map answers
         * "not a pointer" to every question, so the guard passed everything and typed
         * `int8_t* j` as LPCRITICAL_SECTION -- the cl gate caught it as C2109 on fn_0007f17c.
         * This is the THIRD pass this session placed before the state it consults (see
         * ret_struct_ty, computed lazily for the same reason). When adding a pass here,
         * check where its inputs are FILLED, not where the call site reads well. */
        propagate_api_types();  /* Win32 types from API contracts onto the locals */

        /* collapse boolean-value diamonds `if(c)X=1;else X=0;` -> `X = c;` BEFORE the
         * short-circuit merge (removes arm blocks that would otherwise fragment it). */
        fold_boolean_diamonds();
        /* Fold short-circuit condition chains, then recompute the CFG analyses the
         * structurer depends on (the merge changes taken/fall/pred). This lets a
         * chain of `&&`/`||` guards structure as one `if` instead of degrading to a
         * goto/state-machine. */
        merge_short_circuit();
        /* Cross-jump identical /O2-duplicated tails into one shared block BEFORE the
         * dominator/loop analysis (it changes taken/fall/pred). Combined with the
         * structurer's high-fan-in goto gate, this collapses the "same tail 3-6x"
         * bloat the analysis flagged into one epilogue + goto/fall-through. */
        merge_identical_tails();
        compute_dominators();
        compute_postdom();
        find_loops();

        /* flag-dispatch multi-exit loops (guarded 2-exit loops) so the shared exit
         * join has a single predecessor and structures goto-free (recomputes CFG). */
        flag_dispatch_multiexit_loops();

        if (std::getenv("DS_DBG_LOOPS") && f && f->rva == (getenv("DS_DBG_RVA") ? strtoull(getenv("DS_DBG_RVA"),0,16) : 0x1ab40)) {
            fprintf(stderr, "[LOOPS] headers:");
            for (auto& kv : loop_of_header) fprintf(stderr, " blk%d(0x%llx)", kv.first, (unsigned long long)blocks[kv.first].addr);
            fprintf(stderr, "\n");
            for (auto& b : blocks)
                for (int s : b.succ)
                    if (rpo_num.size() > (size_t)s && rpo_num[s] <= rpo_num[b.id] && s != b.id) {
                        bool dom = dominates(s, b.id);
                        fprintf(stderr, "[RETREAT] %d(0x%llx) -> %d(0x%llx)  dominated=%d %s\n",
                                b.id, (unsigned long long)blocks[b.id].addr, s, (unsigned long long)blocks[s].addr,
                                (int)dom, dom ? "(natural loop)" : "(IRREDUCIBLE)");
                    }
        }

        /* recover per-function struct layouts for pointer params (conservative, with
         * raw fallback) so `*(int*)((char*)a1 + 0x140)` renders `a1->field_140`. */
        recover_struct_layouts();
        detect_lock_fields();   /* CRITICAL_SECTION struct fields (needs param_structs) */
        detect_tls_index();     /* name the _tls_index global from the gs:[0x58]+G*8 pattern */
        detect_stl_vectors();            /* _Mylast-_Myfirst range idiom -> name a std::vector's fields */
        detect_stl_strings();            /* _Myres-vs-15 SSO discriminator -> name a std::string's fields */
        unify_struct_aliases();          /* merge proven-aliased per-fn structs (field UNION) into one type */
        detect_self_ref_fields();        /* linked-list/tree: a field that points to its own struct -> struct S* */
        _phase("struct-recovery");
        recover_operator_new();          /* alloc-then-vtable-store callee -> operator_new / void*(size_t) */
        assign_global_struct_locals();   /* cache read-only global struct bases in locals */
        propagate_local_class_tags();    /* class tag along local copy chains -> devirt on a local */
        coalesce_locals();   /* AFTER struct recovery so decl_type (including struct-ptr, float,
                              * pointer) is final: the candidate gate decl_type(x)==decl_type(y)
                              * would else merge a to-be-struct-ptr var with a float var (C2440). */
        inline_invariant_temps();   /* slash the residual temp cloud (SSA-invariant recompute) */
        inline_local_loads();       /* + same-block field/array loads with no aliasing store between */
        fold_return_temps();         /* `v = e; return v;` -> `return e;` (Hex-Rays return shape) */
        fold_dead_block_temps();     /* inline a reused temp confined to a returning block (`v=0;*(a1)=v;return` -> `*(a1)=0`) */

        /* post-typing idiom rewrites (unsigned range-check -> x>=lo && x<=hi, etc.).
         * Pure expression rewrite; no CFG/goto impact. Default-on; DS_NO_IDIOM disables. */
        if (!std::getenv("DS_NO_IDIOM")) recognize_idioms();
        detect_for_loops();   /* after idioms so H.cond matches the emitted condition */
        compute_autonames();  /* after for-loops (consumes induction_var_of_header) */
        scrub_in_placeholders();     /* HARD GUARANTEE: no in_<X> phantom ever reaches output */
        narrow_temp_widths();        /* D1: long long -> int for provably-32-bit-value temps */
        compute_display_renumber();  /* v#/t# -> contiguous v1,v2,... (Hex-Rays naming) */
        /* H2: per-function struct tags were minted `s_<fn>_t1272` at struct-build time, BEFORE
         * the display renumber turned the var into `v97` — so the tag references a temp id that
         * appears nowhere in the body. Re-mint each temp-keyed tag from the var's DISPLAY name so
         * `struct s_<fn>_v97 *v97` reads consistently and is as diff-stable as the vars. Every emit
         * site reads L.tag/fptr_tag, so mutating the stored strings keeps forward-decl, struct-def,
         * decl_type and field casts in lockstep. Class (RTTI) tags and param/global/nested/`sN`
         * tags have no autoname entry and are left untouched; a name collision declines the rename. */
        if (!std::getenv("DS_NO_RENUM")) {
            std::set<std::string> taken;
            for (auto& kv : param_structs)
                if (kv.second.is_class || !autoname.count(kv.first)) taken.insert(kv.second.tag);
            std::map<std::string,std::string> remap;
            for (auto& kv : param_structs) {
                if (kv.second.is_class || !autoname.count(kv.first)) continue;
                std::string nt = "s_" + self_fname + "_" + autoname[kv.first];
                if (nt == kv.second.tag) { taken.insert(nt); continue; }
                if (taken.count(nt)) continue;              /* would collide -> keep raw tag */
                taken.insert(nt); remap[kv.second.tag] = nt; kv.second.tag = nt;
            }
            for (auto& kv : param_structs)                  /* re-point nested `struct T*` field refs */
                for (auto& ft : kv.second.fptr_tag) {
                    auto r = remap.find(ft.second);
                    if (r != remap.end()) ft.second = r->second;
                }
        }
        recover_stack_strings();   /* annotate `char sN[]` decls whose bytes were built from immediates */
        late_peephole();      /* final value-identical readability folds (nested casts, x+-K, cmp-normalize) */

        /* REACHING-FLAG STRUCTURING: REMOVED. The cross-join set stays empty, so
         * emit_if_else never lifts a proper region and no `__at_<addr>` flag is emitted.
         *
         * Boehm-Jacopini says any reducible CFG can be rendered goto-free with enough
         * boolean flags, and that is what this did — driving NullWare's goto count down to
         * ~142. The flags are a LIE OF PROVENANCE though: `__at_1f80` does not exist in the
         * binary. A function came out as
         *     char __at_1f80 = 0, __at_1ff9 = 0, __at_215d = 0, __at_21b1 = 0, ...;
         *     ... __at_1f80 = 1; ... if (__at_1f80) { ...
         * i.e. eight invented booleans standing in for control flow the machine expresses
         * directly. Hex-Rays — the parity target — never does this: it emits a real `goto`
         * and lets the reader see the edge. A goto is IN the binary; `__at_1f80` is not.
         *
         * Measured cost of removing it, whole-binary A/B: gotos 142 -> 637 across 53 -> 154
         * of 1497 functions, chars +0.4% (10,526,333 -> 10,567,583). So ~120 functions of
         * invented control flow become ~101 functions with honest gotos, at no size cost.
         * The GOTO_TOTAL gate threshold moved with it — see _qa/scripts/fast_gate.sh. That metric
         * was always a readability PROXY, and this is the case where the proxy and the goal
         * disagree: optimising it further meant printing flags instead of edges. */
        cross_joins.clear();
        in_flag_region = false;
        flag_trial_budget = 0;

        /* pointer-vs-0 -> NULL. MUST run before the body is rendered below (the pointer
         * types it consults are already final from propagate_pointer_types). */
        mark_null_consts();

        /* ---- emit body ---- */
        _phase("pre-emit(naming/loops)");
        std::string body;
        indent_lvl = 1;
        out.clear();
        bool ok_struct = false;
        try {
            auto reset_emit = [&]{
                structured.clear(); threaded.clear(); struct_guard = 0; struct_bailed = false;
                eff_join_cache.clear(); loop_pd.clear(); active_loop_sinks.clear();   /* per-function */
                /* Both reset PER PASS, not per function. The discovery pass and the
                 * real pass must make IDENTICAL emission decisions (pass 1 exists
                 * only to learn which blocks become goto targets); if pass 1 could
                 * leave the budget/memo depleted, pass 2 would structure differently
                 * and its gotos would dangle. Same starting state -> same
                 * deterministic sequence -> same exhaustion point in both. */
                trial_failed.clear();   /* trial memo is scoped to one emit pass */
                dup_work = 0;
                emit_work = 0;
                /* loop_fwd_sink is populated by flag_dispatch (pre-emit) and must survive reset_emit's
                 * retries; it is cleared at flag_dispatch start, not here. */
                dup_budget = std::getenv("DS_NO_DUP") ? 0 : 160;   /* tail-duplication budget (kept modest: raising it bloats diamonds exponentially — the effective-join trial emits shared joins ONCE instead of duplicating). */
                indent_lvl = 1; cur_loop_header = -1; cur_loop_follow = -1;
                for (int m : merged_blocks) structured.insert(m);
            };
            /* PASS 1 (discovery): a `goto L_x` dangles when L_x was already emitted
             * INLINE without a label (need_label wasn't set yet because the goto is
             * emitted after the block). Historically that reverted the WHOLE function
             * to a flat goto-CFG — the "goto soup". Instead, run emission once to
             * DISCOVER every block that becomes a goto target (need_label accumulates
             * these), then re-emit: pass 2 prints those labels inline so the gotos
             * resolve and the function keeps its structure. need_label carries over
             * between the passes; emission decisions do not depend on it, so the two
             * passes produce identical structure. */
            need_label.clear();
            reset_emit();
            std::string scratch;
            {
                emit_region(entry_block(), -1, scratch, -1);
                for (auto& b : blocks) {
                    if (budget_tripped) break;   /* deadline: stop driving new regions */
                    if (structured.count(b.id) || b.insn_idx.empty()) continue;
                    need_label.insert(b.id);
                    emit_region(b.id, -1, scratch, -1);
                }
            }
            _phase("emit-pass1(discover)");

            /* PASS 2 IS OFTEN UNNECESSARY. It exists for one situation: a `goto L`
             * whose target was already emitted INLINE, before the goto revealed
             * that it needed a label. Re-emitting with need_label pre-populated
             * fixes that. But if pass 1 came out label-consistent then no goto is
             * dangling, every target that needed a label already got one, and pass
             * 2 would re-derive the identical text — the two passes make the same
             * structural decisions by construction, and any label pass 2 adds for
             * an already-consistent body is unreferenced and removed by
             * prune_dead_labels below.
             *
             * Most functions contain no gotos at all, so this skips a full second
             * emission for the large majority of them. Measured: pass 1 and pass 2
             * cost the same, and together they were ~40% of total decompile time.
             *
             * A pass-1 BAILOUT still falls through to pass 2: reset_emit() clears
             * struct_bailed on purpose, and pass 2 runs with better input (the
             * discovered labels), so it frequently structures cleanly where pass 1
             * gave up. Short-circuiting that reverted those functions to goto-CFG. */
            std::string tmp;
            if (!struct_bailed && !budget_tripped && labels_consistent(scratch)) {
                tmp.swap(scratch);
            } else {
            /* PASS 2 (real): need_label now holds all goto targets from pass 1. */
            reset_emit();
            emit_region(entry_block(), -1, tmp, -1);
            for (auto& b : blocks) {
                if (budget_tripped) break;   /* deadline: stop driving new regions */
                if (structured.count(b.id)) continue;
                if (b.insn_idx.empty()) continue;
                need_label.insert(b.id);
                emit_region(b.id, -1, tmp, -1);
            }
            }
            /* Repair pass: catch any residual dangling target (a block reached only
             * via duplication, so pass 1 didn't canonically label it). */
            for (size_t guard = 0; guard <= blocks.size() && !budget_tripped; ++guard) {
                std::vector<int> dang = dangling_label_blocks(tmp);
                bool progress = false;
                for (int id : dang) {
                    if (structured.count(id)) continue;  /* will get its label */
                    need_label.insert(id);
                    indent_lvl = 1;
                    emit_region(id, -1, tmp, -1);
                    progress = true;
                }
                if (!progress) break;
            }
            _phase("emit-pass2+repair");
            /* Drop provably-unreachable statements (a `goto`/stmt after an
             * unconditional transfer) — including any the repair pass just emitted.
             * Run AFTER repair so repaired regions are cleaned too. */
            if (!std::getenv("DS_LEGACY_SM"))
                tmp = strip_unreachable_after_terminator(tmp);
            body = tmp;
            /* The whole-function reaching-flag fallback lived here and is REMOVED for the
             * same reason as the scoped lift above: it re-emitted a function whose gotos
             * survived structuring as one flag chain, which is provably goto-free and
             * provably unreadable. It even needed a "soup guard" to decide when its own
             * output was too soupy to accept — a tell that the mechanism was fighting the
             * goal. A residual goto now simply stays a goto. */
            /* A tripped struct_guard means the structured body DROPPED a region
             * (emitted `/* structurer bailout *\/` and returned) — it is incomplete
             * and must NOT be accepted, however label-consistent the truncated text
             * looks. Force the complete goto-CFG fallback (linear, no recursion
             * guard, never loses a block) instead of silently emitting partial code. */
            /* A deadline trip also invalidates the attempt: the drivers stopped
             * early, so the body may be missing whole regions even when what DID
             * get emitted happens to be label-consistent. Fall through to the
             * complete goto-CFG, which never loses a block. */
            ok_struct = labels_consistent(body) && !struct_bailed && !budget_tripped;
        } catch (...) {
            ok_struct = false;
        }
        if (!ok_struct) {
            /* structured emission still left a dangling goto (e.g. the dangling
             * target was itself already structured inline, so no fresh region
             * could be emitted) or threw: fall back to the always-correct labeled
             * goto-CFG. */
            /* The reverted-to-goto form is a legitimate (correct) fallback, so the
             * production output carries no marker. The diagnostic comment (and the
             * failed structured attempt) is emitted only under DS_DBG_BODY. */
            std::string dbg;
            if (std::getenv("DS_DBG_BODY")) {
                std::vector<int> dang = dangling_label_blocks(body);
                dbg = "/* DBG reverted; dangling:";
                for (int d : dang) dbg += " " + block_label(d);
                dbg += " */\n";
                dbg += "/* ---- failed structured attempt ----\n" + body + "\n---- end ---- */\n";
            }
            indent_lvl = 1;
            std::string tmp;
            /* The structured attempt was label-INCONSISTENT (a dangling goto the
             * two-pass + repair could not resolve) or the guard tripped. Emit the
             * complete labeled goto-CFG — the ZERO-GOTO GUARANTEE pass just below
             * then converts it to a loop-switch state machine, so no goto survives. */
            emit_goto_cfg(tmp);
            body = dbg + tmp;
        }
        body = prune_dead_labels(body);
        body = dedupe_label_defs(body);   /* guarantee no duplicate label survives -> always compiles */
        /* MINIMAL-GOTO policy (Hex-Rays / IDA style). The recursive structurer tries
         * as hard as it can — two-pass label discovery, short-circuit &&/|| merging,
         * guard-clause inlining, bounded tail duplication — to recover real if/else/
         * loop structure. When it SUCCEEDS (ok_struct) but leaves a SMALL number of
         * residual gotos, those are genuinely-irreducible cross-edges it provably
         * could not remove: an SSE strcmp's byte<->qword loops that jump into each
         * other, a retry latch with two SCC entries. That structured-with-a-few-gotos
         * form is EXACTLY what Hex-Rays emits and reads far better than flattening the
         * whole function into `while(1) switch(__state)`. So KEEP it.
         *
         * Convert to a state machine ONLY when structure genuinely could not be
         * recovered: the flat goto-per-block emit_goto_cfg fallback (!ok_struct), or a
         * residual goto count above the threshold (a messy multi-target tangle where
         * the SM is no worse). DS_MAX_GOTO tunes the threshold; DS_FORCE_SM restores
         * the old strict zero-goto behaviour for A/B measurement. */
        int goto_n = 0;
        std::set<std::string> goto_tgts;
        for (size_t gp = 0; (gp = body.find("goto ", gp)) != std::string::npos; ) {
            gp += 5;
            size_t e = gp;
            while (e < body.size() && body[e] != ';' && body[e] != '\n' && body[e] != ' ') ++e;
            goto_tgts.insert(body.substr(gp, e - gp));
            ++goto_n;
        }
        /* THE STATE-MACHINE TOGGLE. Default OFF: a function's gotos stay plain gotos, which
         * read far better than flattening the whole thing into a dispatch loop (that was the
         * mandatory behaviour removed in 8cb9097). DS_FORCE_SM turns it ON: EVERY function that
         * still has a goto is re-emitted as `while(1) switch(__state)` with ZERO gotos.
         * This is the "make every goto a state machine forever" option -- the UI wires a
         * persistent checkbox to this env var. It is always POSSIBLE (Böhm-Jacopini); it is
         * just less readable, which is why it is a choice, not the default.
         * goto_n / goto_tgts are also counted above for the confidence header. */
        if (goto_n > 0 && std::getenv("DS_FORCE_SM")) {
            std::string sm;
            indent_lvl = 1;
            emit_state_machine(sm);
            body = sm;
        }

        /* Hex-Rays-style else-if chains: fold `} else {\n if(...){...} \n}` staircases
         * (we otherwise emit ZERO else-if). Runs on the FINAL body (structured or SM). */
        body = collapse_and_guards(body);   /* if(A){if(B){}} -> if(A && B){} */
        body = collapse_else_if(body);      /* } else { if(){} } -> } else if(){} */

        /* ---- PROVABLY-CORRECT IRREDUCIBILITY REPORT (DS_IRRED_REPORT=<path>) ----
         * Emit one CSV row per function so an aggregator can answer, with a proof-
         * backed graph property, how many goto-emitting functions are TRULY
         * irreducible (their gotos are mathematically unavoidable) vs merely a
         * structurer limitation. Fully inert unless the env var is set. */
        if (const char* rp = std::getenv("DS_IRRED_REPORT")) {
            int final_gotos = 0;
            for (size_t gp = 0; (gp = body.find("goto ", gp)) != std::string::npos; gp += 5) ++final_gotos;
            int nreach = 0; {
                int n = (int)blocks.size();
                std::vector<char> reach(n, 0);
                if (n) { std::vector<int> st{0}; reach[0] = 1;
                    while (!st.empty()) { int b = st.back(); st.pop_back();
                        for (int s : blocks[b].succ) if (s >= 0 && s < n && !reach[s]) { reach[s] = 1; st.push_back(s); } } }
                for (int b = 0; b < n; ++b) nreach += reach[b];
            }
            bool reducible = cfg_is_reducible();
            const char* form = (body.find("switch (__state") != std::string::npos || body.find("switch(__state") != std::string::npos)
                                   ? "state-machine" : (final_gotos > 0 ? "kept-goto" : "structured");
            if (FILE* fp = fopen(rp, "ab")) {
                fprintf(fp, "%llx,%d,%d,%d,%s\n", (unsigned long long)f->rva, nreach,
                        reducible ? 1 : 0, final_gotos, form);
                fclose(fp);
            }
        }

        /* ---- header + declarations ---- */
        std::string fname = (f->name[0] ? sani(std::string(f->name))
                                        : "sub_" + hex(f->rva).substr(2));
        std::string ret_t;
        if (!used_return) ret_t = "void";
        else if (ret_conflict_raw) ret_t = "long long";   /* mixed float+pointer return */
        else if (ret_small_w == 1) ret_t = ret_small_uns ? "unsigned char" : "signed char";
        else if (ret_small_w == 2) ret_t = ret_small_uns ? "unsigned short" : "short";
        else if (ret_byte_return) ret_t = "unsigned char";   /* bool/char in al */
        else if (ret_is_float) ret_t = (ret_width >= 8) ? "double" : "float";
        else if (ret_is_pointer) {
            if (!ret_struct_ty().empty())    /* returns a recovered struct pointer, not a scalar */
                ret_t = ret_struct_ty();
            else if (ret_ptr_elem_float)
                ret_t = (ret_ptr_elem_w >= 8 ? "double" : "float") + std::string("*");
            else if (ret_ptr_elem_w > 0)
                ret_t = typ_str(ret_ptr_elem_w, ret_ptr_elem_uns, false) + "*";
            else ret_t = "long long";
        } else ret_t = typ_str(ret_width >= 8 ? 8 : 4, ret_is_unsigned, false);

        /* This function's OWN Win32 return type, if build_sig_table propagated one across the
         * call graph (a wrapper that hands back an API's result returns that API's type):
         *     int64_t f_get_base(void)  ->  HMODULE f_get_base(void)
         * Without it the wrapper and its caller disagree -- the caller says `HMODULE m = ...`
         * while the callee it reads says it returns int64_t.
         * Only replaces a width-derived INTEGER spelling: void/float/double/pointer/narrow all
         * carry information the table does not, and a pointer especially must not be flattened
         * to an integer-backed typedef (that is the C2109 class). */
        if (sigtab && f && used_return && !ret_is_pointer && !ret_is_float &&
            !ret_conflict_raw && ret_small_w == 0 && !ret_byte_return) {
            auto si = sigtab->find(f->rva);
            if (si != sigtab->end() && !si->second.ret_api.empty()) {
                ret_t = si->second.ret_api;
                api_types_used.insert(ret_t);
            }
        }

        _phase("emit-body");
        compute_bool_vars();   /* flag locals -> `bool` (needs the FINAL var widths) */
        _phase("compute_bool_vars");

        /* Prune TRAILING unused parameters from the signature. ABI/register
         * recovery over-counts args (a float-only `acosf(float)` gets phantom
         * int64 a2/a3 from rcx/rdx + a float a4), so drop trailing params whose
         * identifier never appears in the emitted body. Body-scan is the safety
         * proof: if `aN` is absent, removing it cannot create an undeclared ref.
         * Guarded: NOT for a self-recursive fn (its self-call arity clamp pads to
         * num_params, so a shorter proto would be C2197), and NOT for a loop-
         * carried homed param (used via a `vN = aN` decl init). DS_NO_PARAMPRUNE. */
        int sig_params = num_params;
        if (num_params > 0 && !std::getenv("DS_NO_PARAMPRUNE")) {
            auto isid = [](char c){ return c=='_' || (c>='0'&&c<='9') || (c>='a'&&c<='z') || (c>='A'&&c<='Z'); };
            bool self_rec = !self_fname.empty() && body.find(self_fname + "(") != std::string::npos;
            auto used = [&](int p) -> bool {
                std::string nm = "a" + std::to_string(p);
                for (auto& kv : slot_init_param) if (kv.second == nm) return true;  /* loop-carried */
                for (size_t pos = 0; (pos = body.find(nm, pos)) != std::string::npos; pos += nm.size()) {
                    bool lb = (pos == 0) || !isid(body[pos-1]);
                    bool rb = (pos+nm.size() >= body.size()) || !isid(body[pos+nm.size()]);
                    if (lb && rb) return true;
                }
                return false;
            };
            if (!self_rec)
                while (sig_params > 0 && !used(sig_params)) --sig_params;
        }
        std::string params;
        if (sig_params == 0) params = "void";
        else {
            for (int i = 0; i < sig_params; ++i) {
                if (i) params += ", ";
                std::string nm = "a" + std::to_string(i + 1);
                std::string ty = decl_type(nm);
                /* pointer types already carry `*`; place name without extra space
                 * collapse so `int* a1` reads cleanly */
                if (!ty.empty() && ty.back() == '*') params += ty + nm;
                else params += ty + " " + nm;
            }
        }

        /* gather the set of var names actually referenced post-DSE */
        std::set<std::string> referenced;
        std::function<void(const ExprP&)> gather = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Var) referenced.insert(e->name);
            gather(e->a); gather(e->b); gather(e->c);
            for (auto& ar : e->args) gather(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { gather(s.lhs); gather(s.rhs); }
            gather(b.cond); gather(b.ret_value); gather(b.switch_var); gather(b.tail_call);
        }

        /* Definite-assignment: a local READ on a path where it was never assigned
         * (a merged return temp returned on an early-exit path BEFORE its assignment
         * -> `return (int)t2` with t2 uninitialized, fun_0002b090) must be zero-init'd
         * so the emitted C has no uninitialized-variable read. A forward "must be
         * assigned on entry" dataflow (intersection over preds). Zero-init of an
         * always-assigned var is dead code, so over-approximation is SAFE. Params,
         * array buffers, and in_<REG> backstops are excluded. */
        std::set<std::string> maybe_uninit;
        {
            int nb = (int)blocks.size();
            std::vector<std::set<std::string>> gen(nb), ubd(nb);
            std::set<std::string> allvars;
            for (int i = 0; i < nb; ++i) {
                std::set<std::string> defd;
                for (auto& s : blocks[i].stmts) {
                    std::set<std::string> reads;
                    collect_var_names(s.rhs, reads);
                    if (s.lhs && s.lhs->kind != EK::Var) collect_var_names(s.lhs, reads);
                    for (auto& r : reads) { allvars.insert(r); if (!defd.count(r)) ubd[i].insert(r); }
                    if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var) {
                        defd.insert(s.lhs->name); allvars.insert(s.lhs->name);
                    }
                }
                std::set<std::string> tr;
                collect_var_names(blocks[i].cond, tr);
                collect_var_names(blocks[i].ret_value, tr);
                collect_var_names(blocks[i].switch_var, tr);
                for (auto& r : tr) { allvars.insert(r); if (!defd.count(r)) ubd[i].insert(r); }
                gen[i] = defd;
            }
            int entry = entry_block();
            std::vector<std::set<std::string>> in(nb), out(nb);
            for (int i = 0; i < nb; ++i) out[i] = allvars;
            bool changed = true; int guard = 0;
            while (changed && guard++ < 200000) {
                if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
                changed = false;
                for (int i = 0; i < nb; ++i) {
                    std::set<std::string> ni; bool first = true;
                    if (i != entry && !blocks[i].pred.empty()) {
                        for (int p : blocks[i].pred) {
                            if (p < 0 || p >= nb) continue;
                            if (first) { ni = out[p]; first = false; }
                            else { std::set<std::string> t; for (auto& v : ni) if (out[p].count(v)) t.insert(v); ni.swap(t); }
                        }
                    }
                    if (first) ni.clear();
                    in[i] = ni;
                    std::set<std::string> no = ni;
                    for (auto& v : gen[i]) no.insert(v);
                    if (no != out[i]) { out[i] = no; changed = true; }
                }
            }
            auto is_param = [](const std::string& n){ return n.size() >= 2 && n[0]=='a' && n[1]>='1' && n[1]<='9'; };
            for (int i = 0; i < nb; ++i)
                for (auto& v : ubd[i])
                    if (!in[i].count(v) && !is_param(v) && v.rfind("in_", 0) != 0 && !array_locals.count(v))
                        maybe_uninit.insert(v);
        }
        /* A homed parameter that is reassigned in the body was split into a live
         * range: reads before the recycle keep the param name, the recycle store
         * and after use a fresh local (home_reuse_local). When that fresh local is
         * only CONDITIONALLY assigned (the `/Od` in-place `if(x<0)x=0;` / min-max
         * swap idiom), its fall-through path still holds the INCOMING parameter —
         * so initialize it to aN, not 0 (the `letter_grade(score)`/`clamp_to_range`
         * "param reads as 0" bug). Only for maybe-uninit locals, so a genuine
         * recycle (slot reused for an unrelated value, always written before read)
         * gets no spurious init. */
        std::map<std::string,std::string> reuse_local_init;
        for (auto& kv : home_reuse_local) {
            auto p = param_home_off.find(kv.first);
            if (p != param_home_off.end() && !kv.second.empty())
                reuse_local_init[kv.second] = p->second;
        }
        /* Loop-carried homed params modeled as one local: init `vN = aN`. */
        for (auto& kv : stack_slot_name) {
            auto p = slot_init_param.find(kv.first);
            if (p != slot_init_param.end()) reuse_local_init[kv.second] = p->second;
        }
        auto uninit_suffix = [&](const std::string& nm) -> std::string {
            if (!maybe_uninit.count(nm)) return std::string();
            auto it = reuse_local_init.find(nm);
            if (it != reuse_local_init.end()) return " = " + it->second;
            return " = 0";
        };

        std::string decls;
        /* stack-array locals: `char bufN[size];` (size from the gap to the next
         * frame object, clamped to a safe range). */
        {
            std::vector<int64_t> offs;
            for (auto& kv : stack_array_name) offs.push_back(kv.first);
            std::vector<int64_t> allslots = offs;
            for (auto& kv : stack_slot_name) allslots.push_back(kv.first);
            for (auto& kv : param_home_off) allslots.push_back(kv.first);
            std::sort(allslots.begin(), allslots.end());
            std::vector<std::pair<int,std::string>> aord;
            for (auto& kv : stack_array_name)
                if (referenced.count(kv.second))
                    aord.push_back({atoi(kv.second.c_str()+3), kv.second});
            std::sort(aord.begin(), aord.end());
            for (auto& pr : aord) {
                int64_t base_off = -1;
                for (auto& kv : stack_array_name) if (kv.second == pr.second) base_off = kv.first;
                int64_t next = base_off + 256;
                for (int64_t o : allslots) if (o > base_off && o < next) next = o;
                int64_t sz = next - base_off;
                if (sz < 16) sz = 16;
                if (sz > 4096) sz = 4096;
                decls += "    char " + pr.second + "[" + std::to_string((long long)sz) + "];" +
                         stack_str_note(pr.second) + "\n";
            }
        }
        /* address-escaped aggregates: `char sN[size];` (out-struct / out-param) */
        for (auto& r : agg_regions) {
            if (!referenced.count(r.name)) continue;
            int64_t sz = r.end - r.base;
            if (sz < 8) sz = 8;
            if (sz > 4096) sz = 4096;
            decls += "    char " + r.name + "[" + std::to_string((long long)sz) + "];" +
                     stack_str_note(r.name) + "\n";
        }
        /* read-only global struct bases cached in typed locals (assign_global_struct_locals):
         * `struct s* gs_X = (struct s*)qword_X;` once, so the body uses `gs_X->field`. */
        for (auto& kv : global_struct_local) {
            auto it = param_structs.find(kv.first);
            if (it == param_structs.end()) continue;
            decls += "    struct " + it->second.tag + "* " + kv.second +
                     " = (struct " + it->second.tag + "*)" + kv.first + ";\n";
        }
        /* locals: stack slots (declared in numeric order, only if used) */
        std::vector<std::pair<int,std::string>> ordered;
        for (auto& kv : stack_slot_name) {
            const std::string& nm = kv.second;
            if (nm.size()>=2 && nm[0]=='a' && nm[1]>='1' && nm[1]<='4') continue;
            if (!referenced.count(nm)) continue;
            int num = nm.size() > 1 ? atoi(nm.c_str()+1) : 0;
            ordered.push_back({num, nm});
        }
        std::sort(ordered.begin(), ordered.end());
        for (auto& pr : ordered) {
            const std::string& nm = pr.second;
            std::string ty = decl_type(nm);
            if (!ty.empty() && ty.back() == '*') decls += "    " + ty + disp(nm) + uninit_suffix(nm) + ";\n";
            else decls += "    " + ty + " " + disp(nm) + uninit_suffix(nm) + ";\n";
        }
        /* temps (calls + phis), numeric order */
        std::set<std::string> alltemps = call_temps;
        for (auto& t : phi_temps) alltemps.insert(t);
        for (auto& t : spill_temps) alltemps.insert(t);
        for (auto& t : cse_temps) alltemps.insert(t);
        std::vector<std::pair<int,std::string>> tord;
        for (auto& nm : alltemps) {
            if (!referenced.count(nm)) continue;
            tord.push_back({nm.size()>1?atoi(nm.c_str()+1):0, nm});
        }
        std::sort(tord.begin(), tord.end());
        for (auto& pr : tord) {
            const std::string& nm = pr.second;
            std::string ty = decl_type(nm);
            if (!ty.empty() && ty.back() == '*') decls += "    " + ty + disp(nm) + uninit_suffix(nm) + ";\n";
            else decls += "    " + ty + " " + disp(nm) + uninit_suffix(nm) + ";\n";
        }
        /* Backstop locals (in_<REG>): the unrecovered-value placeholders are not
         * stack slots or temps, so declare each referenced one explicitly. Without
         * this the value is honest but the C is uncompilable (an undeclared
         * identifier) — which is itself a defect. Sorted for stable output. */
        std::vector<std::string> uord;
        for (auto& kv : unknown_reg_name)
            if (referenced.count(kv.second)) uord.push_back(kv.second);
        std::sort(uord.begin(), uord.end());
        for (auto& nm : uord) {
            std::string ty = decl_type(nm);
            if (!ty.empty() && ty.back() == '*') decls += "    " + ty + nm + ";\n";
            else decls += "    " + ty + " " + nm + ";\n";
        }

        /* FINAL BACKSTOP for undeclared temps. Every declaration set above is
         * OPT-IN: a temp is declared only if some pass registered it in
         * call_temps/phi_temps/spill_temps/cse_temps (or it is a stack slot).
         * A value materialized into a fresh `t<N>` by a pass that forgot to
         * register it (e.g. a cmov ternary hoisted to `t = c?x:y; return t;`,
         * or a phantom stack slot `v<N>` below rsp in a hand-written thunk) then
         * reaches the body as an UNDECLARED identifier — honest value, but
         * uncompilable C, which is itself a defect. Declare any referenced
         * `t<N>`/`v<N>` local no earlier set covered. Mirrors the in_<REG>
         * backstop above; a no-op when every temp was already registered. */
        {
            std::set<std::string> slotnames;
            for (auto& kv : stack_slot_name) slotnames.insert(kv.second);
            std::vector<std::string> orphan;
            for (const auto& nm : referenced) {
                if (nm.size() < 2 || (nm[0] != 't' && nm[0] != 'v')) continue;
                bool alldig = true;
                for (size_t i = 1; i < nm.size(); ++i)
                    if (!(nm[i] >= '0' && nm[i] <= '9')) { alldig = false; break; }
                if (!alldig) continue;
                if (alltemps.count(nm) || slotnames.count(nm)) continue;
                orphan.push_back(nm);
            }
            std::sort(orphan.begin(), orphan.end(),
                      [](const std::string& a, const std::string& b){
                          return atoi(a.c_str()+1) < atoi(b.c_str()+1); });
            for (const auto& nm : orphan) {
                std::string ty = decl_type(nm);
                if (!ty.empty() && ty.back() == '*') decls += "    " + ty + disp(nm) + uninit_suffix(nm) + ";\n";
                else decls += "    " + ty + " " + disp(nm) + uninit_suffix(nm) + ";\n";
            }
        }

        std::string protos;
        /* `while (true)` uses the C99 `true` macro, which is only in scope with
         * <stdbool.h> under /TC (C mode) — without it every loop is C2065. The header
         * is include-guarded, so it is safe when many pair-files concatenate into one
         * TU. (A no-op in C++.) */
        if (used_while_true) protos += "#include <stdbool.h>\n";
        /* NULL is not declared by <stdint.h>; <stddef.h> is its C home. */
        if (used_null) protos += "#include <stddef.h>\n";
        /* recovered struct layouts for pointer params: one packed typedef each, emitted
         * before the body so `struct s_aN* aN` and `aN->field_N` resolve. */
        /* forward-declare every tag first so a `struct <nested>*` field resolves regardless
         * of definition order (nested-pointer field retyping). RTTI class types use the `class`
         * keyword (matched in fwd-decl + def to avoid a class/struct mismatch); the shim makes
         * `class` compile as `struct` under /TC and is a no-op under C++. */
        bool any_class_kw = false;
        for (auto& kv : param_structs)
            if (kv.second.is_class && !kv.second.cls_kw_struct) { any_class_kw = true; break; }
        if (any_class_kw)
            protos += "#ifndef __DS_CLASSKW\n#define __DS_CLASSKW\n#ifndef __cplusplus\n"
                      "#define class struct\n#endif\n#endif\n";
        /* Dedupe by TAG: distinct params can share a tag (both a Vec3, or the same
         * recovered class), and per-fn `s_<fn>_<p>` tags are already unique — so one
         * forward decl + one typedef per tag (the include guard made it compile-safe,
         * but emitting `struct Vec3 {...}` twice per function is just noise). */
        std::set<std::string> emitted_tags;
        for (auto& kv : param_structs) {
            if (!emitted_tags.insert(kv.second.tag).second) continue;
            const char* kw = (kv.second.is_class && !kv.second.cls_kw_struct) ? "class " : "struct ";
            protos += kw + kv.second.tag + ";\n";
        }
        emitted_tags.clear();
        for (auto& kv : param_structs) {
            if (!emitted_tags.insert(kv.second.tag).second) continue;
            protos += struct_typedef_str(kv.second);
        }
        /* extern decls for the vtable symbols referenced by `obj->__vftable = &<Class>__vftable`
         * (populated during body emit). The /TC gate compiles (no link), so extern is fine. */
        for (auto& v : referenced_vtables) protos += "extern void* " + v + ";\n";
        /* data imports (std::cout / std::cin / ...) referenced by an IAT load: the
         * slot's value is the imported object's address, so model it as a pointer. */
        for (auto& v : imported_data)
            if (!extern_callees.count(v)) protos += "extern void* " + v + ";\n";
        /* resolved virtual methods called by name need a proto (the /TC gate compiles
         * each function alone). K&R `()` so any arg count compiles. */
        for (auto& v : virtual_callees)
            if (!extern_callees.count(v)) protos += "long long " + v + "();\n";
        /* named absolute-address globals (qword_174148 etc.): one #define each,
         * semantics-preserving, so the body reads `qword_174148` not the repeated
         * `*(long long*)0x174148`. */
        for (auto& kv : named_globals)
            protos += "#define " + kv.first + " " + kv.second + "\n";
        if (used_mulh) {
            /* MSVC intrinsics for the high half of a 64-bit multiply (magic-number
             * division). Declaring them keeps the recompiled TU self-contained. */
            protos += "long long __mulh(long long, long long);\n";
            protos += "unsigned long long __umulh(unsigned long long, unsigned long long);\n";
        }
        if (used_mxcsr) {
            protos += "unsigned int __readmxcsr(void);\n";
            protos += "void __writemxcsr(unsigned int);\n";
        }
        if (used_fabs) {
            /* self-contained definitions (not prototypes): `fabsf` is header-inline
             * in MSVC with no CRT export, so a bare prototype leaves it unresolved
             * at link. `__`-names avoid the reserved-identifier/builtin conflict and
             * read as pure intrinsics for CSE. Include-guarded so concatenating many
             * decompiled functions into one TU does not redefine the body. */
            protos += "#ifndef __DS_FABS_DEFINED\n#define __DS_FABS_DEFINED\n";
            protos += "static double __fabs(double x){ return x<0.0?-x:x; }\n";
            protos += "static float __fabsf(float x){ return x<0.0f?-x:x; }\n";
            protos += "#endif\n";
        }
        if (used_u2f) {
            /* reinterpret a 32-bit pattern as a float (bits-to-float), the write side
             * of the movd xmm,r bit round-trip. Union type-pun is well-defined in C
             * and compiles + runs standalone. Include-guarded for concatenated TUs. */
            protos += "#ifndef __DS_U2F_DEFINED\n#define __DS_U2F_DEFINED\n";
            protos += "static float __u2f(unsigned int __b){ union { unsigned int u; float f; } __x; __x.u = __b; return __x.f; }\n";
            protos += "#endif\n";
        }
        if (used_f32hi) {
            /* clear a float's low 16 mantissa bits — the Dekker high-part split used for
             * extra-precision products (`hi*hi`, `hi + lo`). Self-contained + guarded. */
            protos += "#ifndef __DS_F32HI_DEFINED\n#define __DS_F32HI_DEFINED\n";
            protos += "static float __f32_hi(float __x){ union { float f; unsigned int u; } __v; __v.f = __x; __v.u &= 0xffff0000u; return __v.f; }\n";
            protos += "#endif\n";
        }
        if (used_min) protos += "#ifndef __min\n#define __min(a,b) ((a)<(b)?(a):(b))\n#endif\n";
        if (used_max) protos += "#ifndef __max\n#define __max(a,b) ((a)>(b)?(a):(b))\n#endif\n";
        if (used_sqrt) {
            /* real CRT exports (unlike header-inline fabsf): a prototype compiles
             * standalone and links against the CRT for the behavioral corpus. */
            protos += "double sqrt(double);\nfloat sqrtf(float);\n";
        }
        if (used_fdiv0) {
            /* volatile so the compiler cannot constant-fold `x / __ds_fzero` back
             * into a compile-time divide-by-zero (C2124); at runtime it is ±inf. */
            protos += "#ifndef __DS_FZERO_DEFINED\n#define __DS_FZERO_DEFINED\n";
            protos += "static volatile double __ds_fzero = 0.0;\n";
            protos += "#endif\n";
        }
        if (used_segread) {
            protos += "unsigned long long __readgsqword(unsigned long long);\n";
            protos += "unsigned long long __readfsqword(unsigned long long);\n";
        }
        if (used_nt_current_teb) {
            /* NtCurrentTeb() as the exact expression it replaces (gs:[0x30]) so the
             * recompiled bytes are unchanged; #ifndef-guarded to avoid a winnt.h clash. */
            protos += "#ifndef NtCurrentTeb\n";
            protos += "#define NtCurrentTeb() ((char *)__readgsqword(0x30))\n";
            protos += "#endif\n";
        }
        if (used_cpuid) {
            protos += "int __cpuid_eax(int, int);\n";
            protos += "int __cpuid_ebx(int, int);\n";
            protos += "int __cpuid_ecx(int, int);\n";
            protos += "int __cpuid_edx(int, int);\n";
        }
        if (used_stos) {
            protos += "void __stosb(unsigned char*, unsigned char, unsigned long long);\n";
            protos += "void __stosw(unsigned short*, unsigned short, unsigned long long);\n";
            protos += "void __stosd(unsigned long*, unsigned long, unsigned long long);\n";
            protos += "void __stosq(unsigned long long*, unsigned long long, unsigned long long);\n";
        }
        /* The _rotl/_rotr family is declared by MSVC's <stdlib.h>, but including it would
         * also drag in abs/div/exit/... any of which a recovered function name could
         * collide with. Declare just the used forms, matching <stdlib.h>'s signatures
         * exactly — the same approach the self-declared __stos and __movs intrinsics
         * below already take. */
        for (const auto& rf : used_rot_fns) {
            if (rf == "_rotl8")       protos += "unsigned char _rotl8(unsigned char, unsigned char);\n";
            else if (rf == "_rotr8")  protos += "unsigned char _rotr8(unsigned char, unsigned char);\n";
            else if (rf == "_rotl16") protos += "unsigned short _rotl16(unsigned short, unsigned char);\n";
            else if (rf == "_rotr16") protos += "unsigned short _rotr16(unsigned short, unsigned char);\n";
            else if (rf == "_rotl")   protos += "unsigned int _rotl(unsigned int, int);\n";
            else if (rf == "_rotr")   protos += "unsigned int _rotr(unsigned int, int);\n";
            else if (rf == "_rotl64") protos += "unsigned long long _rotl64(unsigned long long, int);\n";
            else if (rf == "_rotr64") protos += "unsigned long long _rotr64(unsigned long long, int);\n";
        }
        if (used_fastfail) protos += "void __fastfail(unsigned int);\n";
        if (used_nearbyint) protos += "float nearbyintf(float);\n";
        for (const std::string& fn : used_mathfn) {
            if (fn == "floorf")     protos += "float floorf(float);\n";
            else if (fn == "ceilf") protos += "float ceilf(float);\n";
            else if (fn == "truncf")protos += "float truncf(float);\n";
            else if (fn == "nearbyintf") protos += "float nearbyintf(float);\n";
            else if (fn == "floor") protos += "double floor(double);\n";
            else if (fn == "ceil")  protos += "double ceil(double);\n";
            else if (fn == "trunc") protos += "double trunc(double);\n";
            else if (fn == "nearbyint") protos += "double nearbyint(double);\n";
            else if (fn == "sqrtf") protos += "float sqrtf(float);\n";
        }
        if (used_rdtsc)  protos += "unsigned long long __rdtsc(void);\n";
        if (used_xgetbv) protos += "unsigned long long _xgetbv(unsigned int);\n";
        if (used_syscall) protos += "unsigned long long __syscall(unsigned int);\n";
        if (used_shift128) {
            protos += "unsigned long long __shiftright128(unsigned long long, unsigned long long, unsigned char);\n";
            protos += "unsigned long long __shiftleft128(unsigned long long, unsigned long long, unsigned char);\n";
        }
        /* The _Interlocked* intrinsics are declared, not #included: <intrin.h> drags in the
         * whole MSVC intrinsic surface and the dumped units are compiled /TC standalone.
         * Signatures match intrin.h exactly, so a real build that DOES include it agrees. */
        /* _byteswap_* : declared, not #included -- same reasoning as the _Interlocked block
         * below. Signatures match intrin.h exactly, so a real build that DOES include it
         * agrees, and MSVC still lowers each back to a single bswap. */
        for (const std::string& bs : used_byteswap) {
            if (bs == "_byteswap_ushort")
                protos += "unsigned short _byteswap_ushort(unsigned short);\n";
            else if (bs == "_byteswap_ulong")
                protos += "unsigned long _byteswap_ulong(unsigned long);\n";
            else if (bs == "_byteswap_uint64")
                protos += "unsigned long long _byteswap_uint64(unsigned long long);\n";
        }
        for (const std::string& il : used_interlocked) {
            if (il == "_InterlockedExchangeAdd")
                protos += "long _InterlockedExchangeAdd(volatile long*, long);\n";
            else if (il == "_InterlockedExchangeAdd64")
                protos += "long long _InterlockedExchangeAdd64(volatile long long*, long long);\n";
            else if (il == "_InterlockedOr")
                protos += "long _InterlockedOr(volatile long*, long);\n";
            else if (il == "_InterlockedOr64")
                protos += "long long _InterlockedOr64(volatile long long*, long long);\n";
            else if (il == "_InterlockedAnd")
                protos += "long _InterlockedAnd(volatile long*, long);\n";
            else if (il == "_InterlockedAnd64")
                protos += "long long _InterlockedAnd64(volatile long long*, long long);\n";
            else if (il == "_InterlockedXor")
                protos += "long _InterlockedXor(volatile long*, long);\n";
            else if (il == "_InterlockedXor64")
                protos += "long long _InterlockedXor64(volatile long long*, long long);\n";
        }
        if (used_movs) {
            protos += "void __movsb(unsigned char*, const unsigned char*, unsigned long long);\n";
            protos += "void __movsw(unsigned short*, const unsigned short*, unsigned long long);\n";
            protos += "void __movsd(unsigned long*, const unsigned long*, unsigned long long);\n";
            protos += "void __movsq(unsigned long long*, const unsigned long long*, unsigned long long);\n";
        }
        /* scas has no MSVC intrinsic at all (unlike __movs/__stos), so the prototype is
         * ours to define: each returns the FINAL rdi, which is what makes the new rdi, the
         * consumed count and the ZF all expressible from one call — see emit_string_scan.
         * _ne is the repne (scan-until-equal) form, _eq the repe (skip-while-equal) one. */
        for (const auto& sf : used_scas_fns) {
            if (sf == "__scasb_ne")      protos += "unsigned long long __scasb_ne(const unsigned char*, unsigned char, unsigned long long);\n";
            else if (sf == "__scasb_eq") protos += "unsigned long long __scasb_eq(const unsigned char*, unsigned char, unsigned long long);\n";
            else if (sf == "__scasw_ne") protos += "unsigned long long __scasw_ne(const unsigned short*, unsigned short, unsigned long long);\n";
            else if (sf == "__scasw_eq") protos += "unsigned long long __scasw_eq(const unsigned short*, unsigned short, unsigned long long);\n";
            else if (sf == "__scasd_ne") protos += "unsigned long long __scasd_ne(const unsigned long*, unsigned long, unsigned long long);\n";
            else if (sf == "__scasd_eq") protos += "unsigned long long __scasd_eq(const unsigned long*, unsigned long, unsigned long long);\n";
            else if (sf == "__scasq_ne") protos += "unsigned long long __scasq_ne(const unsigned long long*, unsigned long long, unsigned long long);\n";
            else if (sf == "__scasq_eq") protos += "unsigned long long __scasq_eq(const unsigned long long*, unsigned long long, unsigned long long);\n";
        }
        /* rep cmps (inlined memcmp) — like scas, no MSVC intrinsic, so we define it. Each
         * takes (src, dst, count) and returns the FINAL rdi, from which the new rsi/rdi, the
         * consumed count and the terminating ZF are all expressible. _eq is repe (compare-
         * while-equal), _ne is repne. See emit_string_cmp. */
        for (const auto& cf : used_cmps_fns) {
            if (cf == "__cmpsb_eq")      protos += "unsigned long long __cmpsb_eq(const unsigned char*, const unsigned char*, unsigned long long);\n";
            else if (cf == "__cmpsb_ne") protos += "unsigned long long __cmpsb_ne(const unsigned char*, const unsigned char*, unsigned long long);\n";
            else if (cf == "__cmpsw_eq") protos += "unsigned long long __cmpsw_eq(const unsigned short*, const unsigned short*, unsigned long long);\n";
            else if (cf == "__cmpsw_ne") protos += "unsigned long long __cmpsw_ne(const unsigned short*, const unsigned short*, unsigned long long);\n";
            else if (cf == "__cmpsq_eq") protos += "unsigned long long __cmpsq_eq(const unsigned long long*, const unsigned long long*, unsigned long long);\n";
            else if (cf == "__cmpsq_ne") protos += "unsigned long long __cmpsq_ne(const unsigned long long*, const unsigned long long*, unsigned long long);\n";
        }
        std::set<std::string> seen_proto;
        /* api_types_used is a MEMBER (not a local here) because propagate_api_types fills it
         * too: a Win32 type can now reach the output via a typed LOCAL and not just via an
         * imported function's prototype, and every name used still needs its typedef. */
        for (auto& kv : extern_callees) {
            const std::string& c = kv.first;
            if (c == fname) continue;
            if (seen_proto.count(c)) continue;
            seen_proto.insert(c);
            /* recovered operator new (recover_operator_new): the honest allocator signature. */
            if (c == "operator_new") { protos += "void* operator_new(unsigned long long);\n"; continue; }
            /* return type must match the callee's definition (same sig table) so
             * the recompiled TU has consistent prototypes. K&R "()" arg list
             * stays compatible with any definition arity. */
            int rk = kv.second;
            /* A callee the sig table typed VOID but whose RESULT IS USED here
             * (`t = c(...)`, `return c(...)`, `... c(...) ...`) must be declared
             * with a value type — assigning/using a void result is a hard error
             * (C2186). Return-type detection under-detects such callees
             * (fun_0006708c returns a value the caller compares to 0). Promote to
             * long long when the body uses the result rather than discarding it as
             * a bare `c(...);` statement. */
            if (rk == 0) {
                std::string pat = c + "(";
                for (size_t pos = 0; (pos = body.find(pat, pos)) != std::string::npos; pos += pat.size()) {
                    size_t j = pos;
                    while (j > 0 && body[j-1] == ' ') --j;
                    char prev = (j > 0) ? body[j-1] : '\n';
                    /* bare statement start => result discarded (void ok); anything
                     * else (`=`, `(`, operator, `return `) => used as a value. */
                    if (prev != '\n' && prev != ';' && prev != '{' && prev != '}') {
                        rk = 2; break;
                    }
                }
            }
            const char* rt = (rk == 0) ? "void"
                           : (rk == 2) ? "long long"
                           : (rk == 3) ? "float"
                           : (rk == 4) ? "double" : "int";
            /* Emit typed params when the callee has FLOAT params: a K&R `()` promotes a
             * `float` arg to `double` at the call (default arg promotion), so a float-bits
             * helper (`f2u`, isnan/frexp) receives the wrong 8-byte value. Integer-only
             * callees keep `()` — compatible with any arity, avoids a wrong-arity hard error. */
            /* Emit typed params when the callee has FLOAT params (only when EVERY float
             * param's width is known — float_typed_mask — else a double copied via movaps
             * before any scalar op would mis-type as float and truncate; K&R `()` is
             * correct for double args, no promotion). callee_typed_proto_arity gates the
             * IDENTICAL condition the call renderer uses to clamp arg counts, so a fixed-
             * arity proto always has matching clamped call sites (no C2197/C2198). */
            std::string pp;
            int tp_pc = 0;
            if (callee_typed_proto_arity(c, tp_pc)) {
                int kargc, kark;
                if (known_api(c, kargc, kark)) {
                    /* known imported API: exact arity from the table. `(void)` for a
                     * 0-arg API — a bare `()` would be K&R (unspecified) again. */
                    std::vector<std::string> apt;
                    if (tp_pc == 0) pp = "void";
                    else if (api_param_types(c, apt) && (int)apt.size() == tp_pc) {
                        /* TYPES ONLY — the arg COUNT still comes from tp_pc, and the size
                         * re-check above is what welds them: known_api()'s argc stays the
                         * sole arity authority, so a typo in the type table can never
                         * desync this proto from its call-site clamp (the C2197/C2198
                         * class). A mismatch silently falls back to `long long`. */
                        for (int p = 0; p < tp_pc; ++p) {
                            if (p) pp += ", ";
                            pp += apt[p];
                            if (apt[p] != "int") api_types_used.insert(apt[p]);
                        }
                    }
                    else for (int p = 0; p < tp_pc; ++p) { if (p) pp += ", "; pp += "long long"; }
                } else {
                    uint64_t crva = strtoull(c.c_str() + 4, nullptr, 16);
                    const FuncSig& s = sigtab->at(crva);
                    for (int p = 0; p < tp_pc; ++p) {
                        if (p) pp += ", ";
                        if (s.float_mask & (1u << p))
                            pp += (s.double_mask & (1u << p)) ? "double" : "float";
                        else pp += "long long";
                    }
                }
            }
            /* The API's REAL return type, when the library knows one:
             *     int64_t GetModuleHandleW(LPCWSTR);   ->   HMODULE GetModuleHandleW(LPCWSTR);
             * `rt` is derived from ret_kind (0 void / 1 int / 2 long long / ...), which is a
             * register-width fact and says nothing about what the value IS. Only override a
             * width-derived integer spelling -- never a void, float or double, where ret_kind
             * carries information the table does not (an API typed here that the engine
             * proved void would otherwise regain a phantom return). Integer-backed, so the
             * call sites are byte-identical. */
            std::string rtv = rt;
            { std::string art = api_ret_type(c);
              /* a LOCAL callee carries its Win32 return type in the sig table, propagated
               * across the call graph by build_sig_table's ret_api fixpoint. Without this the
               * caller's prototype and the callee's definition CONTRADICT each other:
               *     HMODULE f_get_base(void) { ... }     <- the definition
               *     int64_t f_get_base();                <- what its caller declares */
              uint64_t crv = 0;
              if (art.empty() && sigtab && callee_rva_of(c, crv)) {
                  auto sit = sigtab->find(crv);
                  if (sit != sigtab->end()) art = sit->second.ret_api;
              }
              bool int_rt = (rtv == "int32_t" || rtv == "int64_t" || rtv == "uint32_t" ||
                             rtv == "uint64_t" || rtv == "int" || rtv == "long long" ||
                             rtv == "unsigned int" || rtv == "unsigned long long");
              if (!art.empty() && int_rt) { rtv = art; api_types_used.insert(art); } }
            protos += rtv + " " + c + "(" + pp + ");\n";
        }

        std::string head = ret_t + " " + fname + "(" + params + ") {\n";
        std::string full = "/* " + fname + " @ " + hex(f->rva) +
                           "  size=" + std::to_string((unsigned long long)f->size) + " */\n";
        full += build_xref_comment();
        /* Only the Win32 names a proto in THIS function actually used, so a function that
         * calls no typed import carries no unused-typedef churn. Repeating an IDENTICAL
         * typedef is legal C, which is what keeps the combined-TU recompile clean when many
         * functions each emit their own. */
        for (const std::string& t : api_types_used)
            full += std::string("typedef ") + api_type_backing(t) + " " + t + ";\n";
        /* CRITICAL_SECTION is an opaque 40-byte lock -- emitted when a struct field was typed
         * as one (the lock-field recovery). Guarded so a combined-TU recompile stays clean. */
        { bool any = false;
          for (auto& kv : param_structs) if (!kv.second.ftype.empty()) { any = true; break; }
          if (any) full += "#ifndef __DS_CRITSEC\n#define __DS_CRITSEC\n"
                           "typedef struct { char _cs[40]; } CRITICAL_SECTION;\n#endif\n"; }
        /* The symbolic API constants this function actually used. #define, not an enum: the
         * value must stay EXACTLY the integer the call site had (an enum would be int-typed and
         * a 0x80000000 GENERIC_READ would not fit), and a repeated identical #define is legal C
         * -- which is what keeps a combined-TU recompile clean when many functions emit their
         * own. Hex-format so it reads like the SDK header it mirrors. */
        for (auto& kv : api_consts_used) {
            char buf[80];
            std::snprintf(buf, sizeof buf, "#define %s 0x%llx\n", kv.first.c_str(),
                          (unsigned long long)kv.second);
            full += buf;
        }
        for (auto& kv : teb_fields_used) {
            char buf[96];
            std::snprintf(buf, sizeof buf, "#define %s 0x%llx  /* TEB */\n", kv.first.c_str(),
                          (unsigned long long)kv.second);
            full += buf;
        }
        full += build_confidence_comment(body, referenced);
        full += thunk_annotation();   /* MI this-adjustor thunk note, if this fn is one */
        if (!protos.empty()) full += protos;
        full += head + eh_annotation() + lock_annotation() + decls;
        if (!decls.empty()) full += "\n";
        full += body;
        full += "}\n";
        if (!std::getenv("DS_NO_STDINT"))
            full = "#include <stdint.h>\n" + apply_stdint_types(full);
        _phase("decls+assembly+stdint");
        return full;
    }

    /* Recovered exception-handling structure (from .pdata/.xdata), emitted as a
     * comment block inside the function so it is compile-safe. SEH __try/__except/
     * __finally comes from __C_specific_handler scope tables; C++ try/catch (with
     * catch types) from __CxxFrameHandler3 FuncInfo. DS_NO_EHANNOT. */
    std::string eh_annotation() {
        if (!petab || !f || std::getenv("DS_NO_EHANNOT")) return "";
        auto it = petab->eh.find(f->rva);
        if (it == petab->eh.end()) return "";
        const EHInfo& eh = it->second;
        std::string s;
        for (const auto& sc : eh.seh) {
            std::string tr = hex(sc.begin) + ".." + hex(sc.end);
            if (sc.target == 0)
                s += "    /* SEH: __try { " + tr + " } __finally { " + hex(sc.filter) + " } */\n";
            else {
                std::string filt = (sc.filter == 1) ? std::string("EXCEPTION_EXECUTE_HANDLER")
                                 : (sc.filter == 0) ? std::string("0")
                                 : (name_for_rva(sc.filter) + "()");
                s += "    /* SEH: __try { " + tr + " } __except( " + filt + " ) { " + hex(sc.target) + " } */\n";
            }
        }
        for (const auto& tb : eh.cpp) {
            s += "    /* C++ EH: try { ... }";
            if (tb.catches.empty()) s += " catch(...)";
            for (const auto& c : tb.catches)
                s += " catch( " + (c.type.empty() ? std::string("...") : c.type + (c.by_ref ? " &" : "")) +
                     " @" + hex(c.handler) + " )";
            s += " */\n";
        }
        return s;
    }

    /* Collect the lock-primitive call sites reachable from one expression. `tk`
     * maps a WRAPPER name to its kind: an Expr holds the callee NAME (produced by
     * name_for_rva), never the target rva, so the sigtab tags are reversed through
     * the same namer. Indirect calls are skipped — a computed target is not a
     * provable lock. */
    static void lock_scan_expr(const ExprP& x, uint64_t at,
                               const std::map<std::string, int>& tk,
                               std::vector<std::pair<std::string, uint64_t>>& acq,
                               std::vector<std::pair<std::string, uint64_t>>& rel) {
        if (!x) return;
        if (x->kind == EK::Call && !x->indirect) {
            int k = lock_api_kind(x->callee);
            if (!k) {
                auto i = tk.find(x->callee);
                if (i != tk.end()) k = i->second;
            }
            if (k == 1) acq.push_back({x->callee, at});
            else if (k == 2) rel.push_back({x->callee, at});
        }
        lock_scan_expr(x->a, at, tk, acq, rel);
        lock_scan_expr(x->b, at, tk, acq, rel);
        lock_scan_expr(x->c, at, tk, acq, rel);
        for (const auto& g : x->args) lock_scan_expr(g, at, tk, acq, rel);
    }

    /* Recovered LOCK structure, emitted as a comment block for the same reason the
     * EH block is: a C translation unit has no lock_guard, and fabricating one
     * would not compile. MSVC lowers std::mutex to _Mtx_lock/_Mtx_unlock and a
     * critical section to Enter/LeaveCriticalSection, but both nearly always sit
     * behind a one-call wrapper (the CRT __acrt_lock(n) idiom), so the sites are
     * matched through the sigtab lock_kind tags rather than by API name alone.
     * The acquire/release SITES are reported, never an invented pairing: which
     * release matches which acquire needs the mutex object identity, and the
     * release on the unwind path lives in a separate EH funclet entirely.
     * DS_NO_LOCKANNOT. */
    std::string lock_annotation() {
        static const bool off = std::getenv("DS_NO_LOCKANNOT") != nullptr;
        if (off) return "";
        std::map<std::string, int> tk;
        if (sigtab)
            for (const auto& kv : *sigtab)
                if (kv.second.lock_kind) tk[name_for_rva(kv.first)] = kv.second.lock_kind;

        std::vector<std::pair<std::string, uint64_t>> acq, rel;
        for (const auto& b : blocks) {
            for (const auto& st : b.stmts) {
                lock_scan_expr(st.lhs, st.addr, tk, acq, rel);
                lock_scan_expr(st.rhs, st.addr, tk, acq, rel);
            }
            lock_scan_expr(b.cond, b.addr, tk, acq, rel);
            lock_scan_expr(b.ret_value, b.addr, tk, acq, rel);
            lock_scan_expr(b.tail_call, b.addr, tk, acq, rel);
            lock_scan_expr(b.switch_var, b.addr, tk, acq, rel);
        }
        if (acq.empty() && rel.empty()) return "";

        /* one line per distinct primitive, sites in first-seen order */
        auto group = [](const std::vector<std::pair<std::string, uint64_t>>& v,
                        const char* verb) {
            std::string out;
            std::vector<std::string> order;
            std::map<std::string, std::vector<uint64_t>> by;
            for (const auto& p : v) {
                if (!by.count(p.first)) order.push_back(p.first);
                by[p.first].push_back(p.second);
            }
            for (const auto& nm : order) {
                out += std::string("    /* LOCK: ") + verb + " " + nm + "() @ ";
                const std::vector<uint64_t>& si = by[nm];
                for (size_t i = 0; i < si.size(); ++i) {
                    if (i) out += ", ";
                    out += hex(si[i]);
                }
                out += " */\n";
            }
            return out;
        };
        std::string s = group(acq, "acquire") + group(rel, "release");
        if (!acq.empty()) {
            uint64_t lo = acq[0].second, hi = 0;
            for (const auto& p : acq) if (p.second < lo) lo = p.second;
            for (const auto& p : rel) if (p.second > hi) hi = p.second;
            if (!rel.empty() && hi > lo)
                s += "    /* LOCK: guarded region " + hex(lo) + ".." + hex(hi) + " */\n";
            else if (rel.empty())
                s += "    /* LOCK: no in-function release; the unlock is in an EH "
                     "funclet or a callee */\n";
        }
        return s;
    }

    /* Rewrite the C base-type names to the stdint.h spelling the user reads at the
     * source level (`unsigned int` -> `uint32_t`, `long long` -> `int64_t`, ...).
     * Purely cosmetic — the underlying types are identical — so a `#include
     * <stdint.h>` keeps every TU compiling. Applied to the FINAL text with a tiny
     * lexer that skips string/char literals and comments (so a recovered string
     * or an inline note is never corrupted) and matches only whole words (so
     * identifiers like point/printf are untouched). char and char* stay char
     * (idiomatic for strings). DS_NO_STDINT. */
    static std::string apply_stdint_types(const std::string& s) {
        struct M { const char* from; const char* to; };
        static const M tbl[] = {   /* longest-first at each position */
            {"unsigned long long", "uint64_t"}, {"unsigned int", "uint32_t"},
            {"unsigned short", "uint16_t"},      {"unsigned char", "uint8_t"},
            {"signed char", "int8_t"},           {"long long", "int64_t"},
            {"short", "int16_t"},                {"int", "int32_t"},
        };
        auto isident = [](char c){ return c=='_' || (c>='0'&&c<='9') || (c>='a'&&c<='z') || (c>='A'&&c<='Z'); };
        std::string out; out.reserve(s.size() + 16);
        for (size_t i = 0; i < s.size(); ) {
            char c = s[i];
            /* pass through string / char literals verbatim */
            if (c == '"' || c == '\'') {
                char q = c; out += c; ++i;
                while (i < s.size()) { out += s[i]; if (s[i] == '\\' && i+1 < s.size()) { out += s[i+1]; i += 2; continue; } if (s[i] == q) { ++i; break; } ++i; }
                continue;
            }
            /* pass through comments verbatim */
            if (c == '/' && i+1 < s.size() && s[i+1] == '/') { while (i < s.size() && s[i] != '\n') out += s[i++]; continue; }
            if (c == '/' && i+1 < s.size() && s[i+1] == '*') { out += "/*"; i += 2; while (i < s.size() && !(s[i]=='*'&&i+1<s.size()&&s[i+1]=='/')) out += s[i++]; if (i < s.size()) { out += "*/"; i += 2; } continue; }
            /* at a word start, try to match a type keyword */
            bool at_word_start = (i == 0) || !isident(s[i-1]);
            if (at_word_start && isident(c)) {
                bool matched = false;
                for (const M& m : tbl) {
                    size_t n = std::strlen(m.from);
                    if (s.compare(i, n, m.from) == 0 && (i+n >= s.size() || !isident(s[i+n]))) {
                        out += m.to; i += n; matched = true; break;
                    }
                }
                if (matched) continue;
                /* skip the rest of this identifier so we don't match mid-word */
                while (i < s.size() && isident(s[i])) out += s[i++];
                continue;
            }
            out += c; ++i;
        }
        return out;
    }

    std::string stub(const std::string& why) {
        std::string fname = (f && f->name[0]) ? sani(std::string(f->name))
                            : ("sub_" + (f ? hex(f->rva).substr(2) : std::string("0")));
        std::string s = why; s += "\n";
        s += "void " + fname + "(void) {\n}\n";
        return s;
    }
};


/* ====================================================================== */
/*  Signature prepass over all functions                                   */
/* ====================================================================== */

/* Scalar-FP destination width: 4 for single (`ss`), 8 for double (`sd`), 0 for
 * a non-scalar-FP write (xorps/movaps clear or move the whole reg — they put a
 * float value in the reg but carry no single/double width of their own). Used to
 * decide a float vs double xmm0 return. */
static int fp_scalar_width(unsigned id) {
    switch (id) {
        case X86_INS_MOVSS: case X86_INS_ADDSS: case X86_INS_SUBSS:
        case X86_INS_MULSS: case X86_INS_DIVSS: case X86_INS_MAXSS:
        case X86_INS_MINSS: case X86_INS_SQRTSS: case X86_INS_RCPSS:
        case X86_INS_RSQRTSS: case X86_INS_CVTSI2SS: case X86_INS_CVTSD2SS:
        case X86_INS_COMISS: case X86_INS_UCOMISS:  /* single-precision compare operands */
        case X86_INS_CVTPD2PS:   /* packed double->single: xmm0 result is a float */
            return 4;
        case X86_INS_MOVSD: case X86_INS_ADDSD: case X86_INS_SUBSD:
        case X86_INS_MULSD: case X86_INS_DIVSD: case X86_INS_MAXSD:
        case X86_INS_MINSD: case X86_INS_SQRTSD: case X86_INS_CVTSI2SD:
        case X86_INS_CVTSS2SD: case X86_INS_CVTPS2PD:
        case X86_INS_CVTDQ2PD:   /* (packed) int32 -> double: xmm result is double */
        case X86_INS_COMISD: case X86_INS_UCOMISD:  /* double-precision compare operands */
            return 8;
        case X86_INS_CVTDQ2PS:   /* int32 -> float: xmm result is a float */
            return 4;
        default: return 0;
    }
}

/* True if eax/rax was zeroed (`xor eax,eax` / `sub eax,eax` / `mov eax,0`) shortly
 * before instruction `setcc_idx` with no intervening rax write — i.e. a `setcc al`
 * there returns a FULL zero-extended int 0/1 (`int f(){return a>b;}`), not a byte. */
static bool eax_zeroed_before(cs_insn* ci, long setcc_idx) {
    for (long j = setcc_idx - 1; j >= 0 && j >= setcc_idx - 8; --j) {
        if (!ci[j].detail) continue;
        cs_x86& jx = ci[j].detail->x86;
        unsigned id = ci[j].id;
        bool self_zero = (id==X86_INS_XOR || id==X86_INS_SUB) && jx.op_count==2 &&
            jx.operands[0].type==X86_OP_REG && jx.operands[1].type==X86_OP_REG &&
            jx.operands[0].reg==jx.operands[1].reg;
        bool mov_zero = id==X86_INS_MOV && jx.op_count==2 &&
            jx.operands[0].type==X86_OP_REG && jx.operands[1].type==X86_OP_IMM &&
            jx.operands[1].imm==0;
        Reg r0; int w0;
        if ((self_zero || mov_zero) && jx.op_count>=1 && jx.operands[0].type==X86_OP_REG) {
            map_reg(jx.operands[0].reg, r0, w0);
            if (r0 == R_RAX) return true;
        }
        /* another write to rax before the zero breaks the widen chain */
        for (int o = 0; o < jx.op_count; ++o)
            if (jx.operands[o].type==X86_OP_REG && (jx.operands[o].access & CS_AC_WRITE)) {
                Reg wr; int ww; map_reg(jx.operands[o].reg, wr, ww);
                if (wr == R_RAX) return false;
            }
    }
    return false;
}

void build_sig_table(ds_engine* e, std::map<uint64_t, FuncSig>& tab) {
    if (!e) return;
    cs_mode mode = (e->arch == DS_ARCH_X64) ? CS_MODE_64 : CS_MODE_32;
    csh h;
    if (cs_open(CS_ARCH_X86, mode, &h) != CS_ERR_OK) return;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    std::map<uint64_t, uint64_t> tail_of;   /* func rva -> tail-call callee rva */
    std::map<uint64_t, uint64_t> lock_thunk_of; /* one-call wrapper rva -> its lone local
                                        * callee, so a wrapper-of-wrapper inherits the
                                        * lock kind in the fixpoint below (tab is filled
                                        * in e->funcs order, so a caller preceding its
                                        * thunk cannot resolve it inline). */
    std::map<uint64_t, uint64_t> fwd_thunk_of; /* PURE-forwarding thunk rva -> target:
                                        * writes NO arg reg before a tail `jmp target`,
                                        * so it forwards its incoming rcx/rdx/r8/r9
                                        * unchanged and its arity == the target's. */

    for (size_t fi = 0; fi < e->func_len; ++fi) {
        const ds_func& f = e->funcs[fi];
        FuncSig sig;
        uint64_t tail_target = 0;
        if (f.rva >= e->image_size) { tab[f.rva] = sig; continue; }
        uint64_t avail = e->image_size - f.rva;
        size_t n = (size_t)((f.size && f.size <= avail) ? f.size : avail);
        if (n > 0x8000) n = 0x8000;
        if (n == 0) { tab[f.rva] = sig; continue; }
        cs_insn* ci = nullptr;
        size_t count = cs_disasm(h, e->image + f.rva, n, f.rva, 0, &ci);
        if (count == 0) { if (ci) cs_free(ci, count); tab[f.rva] = sig; continue; }
        if (count > 4000) count = 4000;

        /* params: highest of rcx,rdx,r8,r9 read before written; or homed.
         * return: does the function set eax/rax meaningfully and end with ret? */
        bool seen_write[4] = {false,false,false,false};
        bool used_arg[4] = {false,false,false,false};
        bool homed_arg[4] = {false,false,false,false};
        /* arg reg p dereferenced (real load/store base, read-before-write) => pointer param */
        bool arg_is_ptr[4] = {false,false,false,false};
        int  arg_ptr_w[4]  = {0,0,0,0};   /* first-seen access width at the deref (pointee hint) */
        /* Homed BEFORE `sub rsp`, i.e. at the very top of the prologue. All four of these is
         * the MSVC x64 va_start idiom and nothing else: a variadic callee must spill rcx/rdx/
         * r8/r9 to their shadow slots so va_arg can walk them as one array, and it does that
         * before it owns a frame. All-four-homed ALONE is not enough — an /Od 4-parameter
         * function also homes all four, but only AFTER `push rbp; mov rbp,rsp; sub rsp,N`. */
        bool homed_presub[4] = {false,false,false,false};
        bool xmm_seen_write[4] = {false,false,false,false};
        bool xmm_used[4] = {false,false,false,false};   /* xmm0-3 read before written => float arg */
        int  xmm_w[4]    = {0,0,0,0};                    /* its scalar-FP width: 4 float / 8 double */
        int  max_stack_arg = 0;    /* highest stack-passed arg index (5th+) seen */
        std::set<int64_t> stk_written; /* rsp-relative disps the callee writes first
                                        * (spills/locals) — NOT incoming args */
        int64_t fs = 0; bool sub_done = false;
        bool writes_eax = false, writes_rax = false, has_ret = false;
        bool saw_call_result = false;
        bool saw_byte_ret = false;  /* a ret whose closest rax write is byte-width al */
        bool saw_wide_ret = false;  /* a ret whose closest rax write is full eax/rax (>=4) */
        int  last_rax_w = 0;       /* width of most recent rax write (mov/arith/call) */
        int  ret_rax_w = 0;        /* widest rax width observed live at a ret */
        bool rax_live_at_ret = false;
        long last_rax_idx = -1000; /* instr index of the most recent rax write */
        bool last_rax_from_call = false;  /* most recent rax write was a CALL result */
        uint64_t last_rax_call_target = 0; /* if from a direct call, the callee rva */
        bool ret_only_from_call = false;   /* every rax-live ret came from a call result */
        bool saw_real_value_ret = false;   /* some ret set rax from a deliberate value */
        uint64_t ret_call_target = 0;      /* callee whose result was taken as the return */
        /* LOCK RECOVERY: is this function a bare wrapper around ONE lock primitive? */
        int lk_calls = 0;          /* call sites of any kind */
        int lk_api = 0;            /* kind of the lock API called */
        int lk_api_calls = 0;      /* call sites hitting a lock API */
        uint64_t lk_local = 0;     /* direct local callee (a thunk-of-thunk link) */
        int lk_local_calls = 0;
        int lk_tail_api = 0;       /* `jmp qword ptr [IAT]` straight to a lock API */
        bool saw_fp_ret_tail = false;  /* some ret does `cvt/fp-op xmm0; ret` (strong float) */
        int  tail_ret_inherit = 0;     /* a tail-call thunk inherits its target's ret_kind */
        bool saw_prior_call = false;   /* a non-tail `call` happened before the tail jmp:
                                        * the function does real work + discards results,
                                        * so its tail jmp is a goto, NOT a `return g()` */
        int  rax_write_count = 0;      /* how many times rax is written in the function */
        int  rax_param_copy = -1;      /* arg pos if rax's ONLY write is `mov rax,argreg` (return-the-param, e.g. memcpy returns dst) */
        /* float/double return: xmm0 set near a ret with rax NOT the live value. */
        int  last_xmm0_fw = 0;     /* scalar-FP width of the most recent xmm0 write */
        int  xmm_fw[16] = {0};     /* tracked scalar-FP width (8 double / 4 float) per xmm,
                                    * so `movaps xmm0,xmmN; ret` inherits the double width
                                    * of the value instead of defaulting to float. */
        long last_xmm0_idx = -1000;
        bool last_xmm0_packed = false;  /* most recent xmm0 write was a PACKED 128-bit
                                         * move (memcpy vector scratch), not a scalar FP
                                         * return — excluded from the ret-proximity test. */
        bool xmm0_live_at_ret = false;
        int  ret_xmm0_w = 0;       /* widest scalar-FP width live at a ret (8>4) */
        /* x87 (32-bit /arch:IA32) float return: the value comes back on the FPU STACK in
         * ST(0), never in xmm0/rax — so both tests above saw nothing and typed the
         * function `void`, which is why every x87 float function decompiled to an empty
         * `void f(void) { return; }`. Track the stack DEPTH instead: a ret reached with a
         * non-empty stack is returning ST(0). MSVC rounds the result through memory and
         * reloads it (`fstp dword [x]; fld dword [x]; ret`), so the width of the last FLD
         * is the return's real width. */
        int  x87_depth = 0;
        bool x87_live_at_ret = false;
        int  x87_ret_w = 0;
        int  last_fld_w = 0;
        /* A forward in-range `jmp` is the "set return value then branch to the
         * shared epilogue" idiom ONLY when the target actually reaches a `ret`
         * without REDEFINING rax/eax. A loop-exit / if-else forward jmp whose
         * target later does `xor eax,eax` (or another rax write) leaves the rax at
         * the jmp DEAD — counting it (lu_decompose's 64-bit matrix-element rax)
         * mis-widened an `int` return to `long long`, corrupting a `return -1`
         * sentinel into `0xffffffff`. */
        auto fwd_jmp_is_epilogue = [&](uint64_t tgt) -> bool {
            long ti = -1;
            for (long j = 0; j < (long)count; ++j)
                if (ci[j].address == tgt) { ti = j; break; }
            if (ti < 0) return false;
            for (long j = ti; j < (long)count && j < ti + 40; ++j) {
                if (!ci[j].detail) return false;
                unsigned id = ci[j].id;
                if (id == X86_INS_RET || id == X86_INS_RETF) return true;
                if (id == X86_INS_JMP || id == X86_INS_CALL ||
                    id == X86_INS_IDIV || id == X86_INS_DIV || id == X86_INS_MUL ||
                    id == X86_INS_IMUL) return false;   /* can't follow / clobbers rax */
                const cs_x86& xx = ci[j].detail->x86;
                for (int k = 0; k < xx.op_count && k < 4; ++k) {
                    if (xx.operands[k].type == X86_OP_REG &&
                        (xx.operands[k].access & CS_AC_WRITE)) {
                        Reg rr; int rw; map_reg(xx.operands[k].reg, rr, rw);
                        if (rr == R_RAX) return false;  /* rax overwritten before ret */
                    }
                }
            }
            return false;
        };
        unsigned last_id = 0;          /* the range's final instruction -- the noreturn trap test */
        for (size_t i = 0; i < count; ++i) {
            cs_insn& c = ci[i];
            last_id = c.id;
            if (!c.detail) continue;
            cs_x86& x = c.detail->x86;
            /* Track each xmm's scalar-FP width. A scalar-FP op (fp_scalar_width!=0)
             * makes ALL its xmm operands that precision; a reg->reg copy inherits the
             * source width (movsd/movss force 8/4). Lets the FP-return detection read
             * the width of a value moved into xmm0 by a `movaps xmm0,xmmN` copy. */
            {
                int opw = fp_scalar_width(c.id);
                if (opw) {
                    for (int k = 0; k < x.op_count && k < 4; ++k)
                        if (x.operands[k].type == X86_OP_REG) {
                            Reg rr; int rw; map_reg(x.operands[k].reg, rr, rw);
                            if (rr >= R_XMM0 && rr <= R_XMM15) xmm_fw[rr - R_XMM0] = opw;
                        }
                }
                bool copy = (c.id==X86_INS_MOVAPS||c.id==X86_INS_MOVUPS||
                             c.id==X86_INS_MOVAPD||c.id==X86_INS_MOVUPD||
                             c.id==X86_INS_MOVDQA||c.id==X86_INS_MOVDQU||
                             c.id==X86_INS_MOVSD||c.id==X86_INS_MOVSS);
                if (copy && x.op_count==2 && x.operands[0].type==X86_OP_REG &&
                    x.operands[1].type==X86_OP_REG) {
                    Reg d,s; int dw,sw; map_reg(x.operands[0].reg,d,dw); map_reg(x.operands[1].reg,s,sw);
                    if (d>=R_XMM0 && d<=R_XMM15 && s>=R_XMM0 && s<=R_XMM15) {
                        int fw = (c.id==X86_INS_MOVSD) ? 8 : (c.id==X86_INS_MOVSS) ? 4
                                                            : xmm_fw[s - R_XMM0];
                        xmm_fw[d - R_XMM0] = fw;
                    }
                }
                /* andps/andpd ABS idiom: the .rdata sign-mask carries the precision,
                 * so the dest width (and thus a leaf `andps xmm0,[mask]; ret` abs
                 * function's return type) is double for a double mask. */
                if ((c.id==X86_INS_ANDPS||c.id==X86_INS_ANDPD) && x.op_count>=2 &&
                    x.operands[0].type==X86_OP_REG &&
                    x.operands[1].type==X86_OP_MEM &&
                    x.operands[1].mem.base==X86_REG_RIP &&
                    x.operands[1].mem.index==X86_REG_INVALID) {
                    Reg d; int dw; map_reg(x.operands[0].reg, d, dw);
                    uint64_t a = c.address + c.size + (uint64_t)x.operands[1].mem.disp;
                    if (d>=R_XMM0 && d<=R_XMM15 && a + 8 <= e->image_size) {
                        uint32_t lo=(uint32_t)e->image[a]|((uint32_t)e->image[a+1]<<8)|
                                    ((uint32_t)e->image[a+2]<<16)|((uint32_t)e->image[a+3]<<24);
                        uint32_t hi=(uint32_t)e->image[a+4]|((uint32_t)e->image[a+5]<<8)|
                                    ((uint32_t)e->image[a+6]<<16)|((uint32_t)e->image[a+7]<<24);
                        int mw = (lo==0xffffffffu&&hi==0x7fffffffu) ? 8 :
                                 (lo==0x7fffffffu&&hi==0) ? 4 :
                                 (lo==0x7fffffffu&&hi==0x7fffffffu) ? (c.id==X86_INS_ANDPD?8:4) : 0;
                        if (mw) xmm_fw[d-R_XMM0] = mw;
                    }
                }
            }
            /* ---- x87 stack depth (see x87_depth above) ---------------------------
             * The popping arithmetic forms are identified by their DE opcode byte, not
             * by id: capstone has NO X86_INS_FADDP (it maps the popping `faddp` to plain
             * X86_INS_FADD), so an id-only test would miscount the stack. */
            switch (c.id) {
                case X86_INS_FLD: case X86_INS_FILD:
                case X86_INS_FLD1: case X86_INS_FLDZ:
                    ++x87_depth;
                    if (c.id == X86_INS_FLD && x.op_count >= 1 && x.operands[0].type == X86_OP_MEM)
                        last_fld_w = x.operands[0].size ? x.operands[0].size : 8;
                    break;
                case X86_INS_FSTP: case X86_INS_FISTP:
                case X86_INS_FCOMP: case X86_INS_FUCOMP:
                case X86_INS_FCOMPI: case X86_INS_FUCOMPI:
                    if (x87_depth > 0) --x87_depth;
                    break;
                case X86_INS_FCOMPP: case X86_INS_FUCOMPP:
                    x87_depth -= 2; if (x87_depth < 0) x87_depth = 0;
                    break;
                case X86_INS_FADD:  case X86_INS_FSUB: case X86_INS_FSUBR:
                case X86_INS_FMUL:  case X86_INS_FDIV: case X86_INS_FDIVR:
                case X86_INS_FSUBP: case X86_INS_FSUBRP:
                case X86_INS_FMULP: case X86_INS_FDIVP: case X86_INS_FDIVRP:
                    if (x.opcode[0] == 0xDE && x87_depth > 0) --x87_depth;   /* popping form */
                    break;
                default: break;
            }
            if (c.id == X86_INS_RET || c.id == X86_INS_RETF) {
                has_ret = true;
                if (x87_depth > 0) {
                    x87_live_at_ret = true;
                    if (last_fld_w) x87_ret_w = last_fld_w;
                }
                /* the return value lives in whichever value register was set
                 * CLOSEST to the ret: rax (int/ptr) or xmm0 (float/double, the SSE
                 * return ABI). The /Od epilogue loads it right before add rsp/ret.
                 * Callee-saved restores (`pop rbx/rsi/rdi/rbp`, leave, `add rsp`)
                 * sit BETWEEN the value write and the ret and must NOT age it out:
                 * map_put's `xor eax,eax; pop rdi; pop rsi; pop rbp; pop rbx; ret`
                 * is 5 insns wide, so the raw <=4 window mis-typed it `void`. */
                long epi = 0;   /* contiguous epilogue-restore block before the ret */
                for (long j = (long)i - 1; j >= 0; --j) {
                    unsigned jid = ci[j].id;
                    if (jid == X86_INS_POP || jid == X86_INS_LEAVE ||
                        jid == X86_INS_ADD) ++epi;
                    else break;
                }
                /* eax is the RETURN value if its last write reaches the ret and is
                 * NOT consumed by a memory store of eax in between. The window is
                 * generous because a `mov eax,<accumulator>` is often trailed by an
                 * out-param store + register restores + epilogue (bitset_scan/
                 * strip_ansi/base64_encode set eax ~7 insns early). But
                 * `movzx eax; mov [r8],eax; ret` (morton_decode — eax computed FOR
                 * the store, then incidentally alive) is excluded by the store
                 * check, avoiding a spurious return on a void out-param function. */
                bool eax_stored = false;
                if (last_rax_idx >= 0)
                    for (long j = last_rax_idx + 1; j < (long)i; ++j) {
                        cs_insn& sj = ci[j]; if (!sj.detail) continue;
                        cs_x86& sx = sj.detail->x86;
                        bool memw = false, raxr = false, raxaddr = false;
                        for (int o = 0; o < sx.op_count; ++o) {
                            if (sx.operands[o].type == X86_OP_MEM) {
                                if (sx.operands[o].access & CS_AC_WRITE) memw = true;
                                /* rax used as a base/index in an address means it
                                 * was a computed array INDEX (matmul's cdqe(i*n+j)
                                 * then `movsd [rcx+rax*8]`), dead after — incidental,
                                 * not a return value. */
                                const x86_op_mem& mm = sx.operands[o].mem;
                                Reg ar; int aw;
                                if (mm.base  != X86_REG_INVALID) { map_reg(mm.base,  ar, aw); if (ar == R_RAX) raxaddr = true; }
                                if (mm.index != X86_REG_INVALID) { map_reg(mm.index, ar, aw); if (ar == R_RAX) raxaddr = true; }
                            }
                            if (sx.operands[o].type == X86_OP_REG && (sx.operands[o].access & CS_AC_READ)) {
                                Reg rr; int rw2; map_reg(sx.operands[o].reg, rr, rw2);
                                if (rr == R_RAX) raxr = true;
                            }
                        }
                        if ((memw && raxr) || raxaddr) { eax_stored = true; break; }
                    }
                /* loop-guard exclusion: a `mov eax,[rsp+counter]` reloaded for a
                 * `cmp eax,n; jge` loop test (then dead) is NOT a return value —
                 * the widened window would otherwise mis-detect matmul's void as
                 * `return a4`. A genuine return is a reg copy/compute into eax, not
                 * a stack reload consumed by a comparison. */
                bool eax_guard = false;
                if (last_rax_idx >= 0 && last_rax_idx < (long)count && ci[last_rax_idx].detail) {
                    /* eax is a LOOP-COUNTER (not a return value) when its last write is
                     * consumed by a `cmp/test` whose conditional jump loops BACKWARD:
                     * `inc eax; cmp eax,edx; jl <back>` leaves the counter (==n) in eax
                     * at the fall-through ret of a VOID loop (arr_clamp/arr_abs). The
                     * backward-jump test distinguishes it from `mov eax,v; cmp eax,0;
                     * jl <fwd>; ret` which genuinely RETURNS the compared value. */
                    for (long j = last_rax_idx + 1; j < (long)i && !eax_guard; ++j) {
                        if (!ci[j].detail) continue;
                        /* a fresh rax write before the cmp means the value we test is
                         * not the one at the ret — stop (avoid false guard). */
                        {
                            cs_x86& wx = ci[j].detail->x86;
                            bool raxw = false;
                            for (int o = 0; o < wx.op_count && o < 2; ++o)
                                if (wx.operands[o].type==X86_OP_REG && (wx.operands[o].access & CS_AC_WRITE)) {
                                    Reg wr; int ww; map_reg(wx.operands[o].reg, wr, ww);
                                    if (wr==R_RAX) raxw = true;
                                }
                            if (raxw && ci[j].id != X86_INS_CMP) break;
                        }
                        if (ci[j].id != X86_INS_CMP && ci[j].id != X86_INS_TEST) continue;
                        cs_x86& cx = ci[j].detail->x86;
                        bool reads_rax = false;
                        for (int o = 0; o < cx.op_count; ++o)
                            if (cx.operands[o].type == X86_OP_REG) {
                                Reg rr; int rw3; map_reg(cx.operands[o].reg, rr, rw3);
                                if (rr == R_RAX) reads_rax = true;
                            }
                        if (!reads_rax) continue;
                        /* the cmp feeds a BACKWARD conditional jump -> loop back-edge */
                        if (j + 1 < (long)count && ci[j + 1].detail) {
                            cs_insn& jc = ci[j + 1];
                            cs_x86& jx = jc.detail->x86;
                            if (jc.id != X86_INS_JMP && jx.op_count >= 1 &&
                                jx.operands[0].type == X86_OP_IMM &&
                                (uint64_t)jx.operands[0].imm < jc.address)
                                eax_guard = true;
                        }
                        /* also the legacy case: a `mov eax,[mem]` reload for a cmp
                         * (matmul) — the reloaded counter, regardless of jump dir. */
                        if (ci[last_rax_idx].id == X86_INS_MOV) {
                            cs_x86& lw = ci[last_rax_idx].detail->x86;
                            if (lw.op_count == 2 && lw.operands[0].type == X86_OP_REG &&
                                lw.operands[1].type == X86_OP_MEM) {
                                Reg dr; int dw; map_reg(lw.operands[0].reg, dr, dw);
                                if (dr == R_RAX) eax_guard = true;
                            }
                        }
                    }
                }
                /* xmm0 is the FP RETURN only if its last write reaches the ret
                 * WITHOUT being consumed by a memory store of xmm0 in between: a
                 * `movss [rdi+4],xmm0` (value computed FOR an out-param store, then
                 * incidentally still live in xmm0 at a bare ret) is NOT a return —
                 * fun_0000d6c0/fun_0001cb60 fill via a1 and have no real FP return.
                 * Mirrors the integer eax_stored guard. */
                /* a self-zeroing `xorps/xorpd/pxor xmm0,xmm0` produces a CONSTANT 0,
                 * commonly a compare operand (`xorps xmm0,xmm0; comiss xmm0,[m]`) — NOT
                 * a deliberate float return. So when the last xmm0 write is that idiom,
                 * ANY later read of xmm0 (incl. a compare) consumes it -> void. A bare
                 * `xorps xmm0,xmm0; ret` (genuine `return 0.0f`) has no such read. */
                bool last_xmm0_is_zero = false;
                if (last_xmm0_idx >= 0 && last_xmm0_idx < (long)count && ci[last_xmm0_idx].detail) {
                    unsigned zid = ci[last_xmm0_idx].id;
                    if (zid == X86_INS_XORPS || zid == X86_INS_XORPD || zid == X86_INS_PXOR) {
                        cs_x86& zx = ci[last_xmm0_idx].detail->x86;
                        if (zx.op_count == 2 && zx.operands[0].type == X86_OP_REG &&
                            zx.operands[1].type == X86_OP_REG &&
                            zx.operands[0].reg == zx.operands[1].reg) last_xmm0_is_zero = true;
                    }
                }
                bool xmm0_stored = false;
                if (last_xmm0_idx >= 0)
                    for (long j = last_xmm0_idx + 1; j < (long)i; ++j) {
                        cs_insn& sj = ci[j]; if (!sj.detail) continue;
                        cs_x86& sx = sj.detail->x86;
                        bool memw = false, xmm0r = false, regw_other = false;
                        for (int o = 0; o < sx.op_count; ++o) {
                            const cs_x86_op& oo = sx.operands[o];
                            if (oo.type == X86_OP_MEM && (oo.access & CS_AC_WRITE)) memw = true;
                            if (oo.type == X86_OP_REG) {
                                Reg rr; int rw5; map_reg(oo.reg, rr, rw5);
                                if (rr == R_XMM0 && (oo.access & CS_AC_READ)) xmm0r = true;
                                if (rr != R_XMM0 && (oo.access & CS_AC_WRITE)) regw_other = true;
                            }
                        }
                        /* xmm0 read and then flowing into MEMORY or into ANOTHER
                         * register via a scalar-FP op (`addss xmm6,xmm0` reduction)
                         * was a temporary feeding a store/accumulation, not the
                         * return value. A bare compare (comiss/ucomiss => fp width 0,
                         * no reg/mem dest) leaves xmm0 intact and does NOT consume it. */
                        if (xmm0r && (memw || (regw_other && fp_scalar_width(sj.id)) || last_xmm0_is_zero)) { xmm0_stored = true; break; }
                    }
                bool rax_close  = (last_rax_w > 0 && ((long)i - last_rax_idx - epi) <= 12 && !eax_stored && !eax_guard);
                /* a last xmm0 write that is an INDEXED memory load (`movss xmm0,
                 * [rcx+rax*4]`) is a loop-body array element left over at the
                 * fall-through ret of a VOID loop (arr_clamp), NOT a return value —
                 * mirrors the eax loop-counter guard. */
                bool xmm0_indexed_load = false;
                if (last_xmm0_idx >= 0 && last_xmm0_idx < (long)count && ci[last_xmm0_idx].detail) {
                    unsigned lid = ci[last_xmm0_idx].id;
                    if (lid == X86_INS_MOVSS || lid == X86_INS_MOVSD) {
                        cs_x86& lx = ci[last_xmm0_idx].detail->x86;
                        if (lx.op_count == 2 && lx.operands[1].type == X86_OP_MEM &&
                            lx.operands[1].mem.index != X86_REG_INVALID)
                            xmm0_indexed_load = true;
                    }
                }
                bool xmm0_close = (last_xmm0_idx >= 0 && ((long)i - last_xmm0_idx - epi) <= 12 &&
                                   !xmm0_stored && !xmm0_indexed_load);
                /* if the LAST non-epilogue instruction before the ret writes xmm0
                 * via a scalar FP op (`movsd xmm0,[maxchange]`), the function
                 * returns float/double in xmm0 — decisive over a stale rax (an
                 * array index from a prior `movsd [..rax..]`) that sits closer in
                 * the linear stream. Fixes the double-returning numerical routines
                 * (jacobi_step/vec_norms/bisect_root/...) mis-typed `long long`. */
                bool fp_ret_tail = false;
                long lastreal = (long)i - 1 - epi;
                if (lastreal >= 0 && ci[lastreal].detail) {
                    int fw2 = fp_scalar_width(ci[lastreal].id);
                    cs_x86& lx = ci[lastreal].detail->x86;
                    unsigned lid = ci[lastreal].id;
                    bool copy_to = (lid==X86_INS_MOVAPS||lid==X86_INS_MOVUPS||
                                    lid==X86_INS_MOVAPD||lid==X86_INS_MOVUPD||
                                    lid==X86_INS_MOVSD||lid==X86_INS_MOVSS);
                    if (lx.op_count >= 1 && lx.operands[0].type == X86_OP_REG) {
                        Reg rr; int rw4; map_reg(lx.operands[0].reg, rr, rw4);
                        if (rr == R_XMM0) {
                            if (fw2) { fp_ret_tail = true; saw_fp_ret_tail = true; if (fw2 > last_xmm0_fw) last_xmm0_fw = fw2; }
                            else if (copy_to && xmm_fw[0]) {   /* movaps xmm0,xmmN of a tracked FP value */
                                fp_ret_tail = true; saw_fp_ret_tail = true;
                                if (xmm_fw[0] > last_xmm0_fw) last_xmm0_fw = xmm_fw[0];
                            }
                        }
                    }
                }
                if (fp_ret_tail || (!last_xmm0_packed && xmm0_close &&
                                    (!rax_close || last_xmm0_idx > last_rax_idx))) {
                    xmm0_live_at_ret = true;
                    int fw = last_xmm0_fw ? last_xmm0_fw : 4;
                    if (fw > ret_xmm0_w) ret_xmm0_w = fw;
                    rax_live_at_ret = false;   /* FP return wins outright */
                } else if (rax_close) {
                    if (last_rax_w > ret_rax_w) ret_rax_w = last_rax_w;
                    rax_live_at_ret = true;
                    /* provenance for the void fixpoint: a ret taking a raw call
                     * result (`... = f(); return`) vs a deliberate value. */
                    if (last_rax_from_call) {
                        ret_only_from_call = true;
                        ret_call_target = last_rax_call_target;
                    } else {
                        saw_real_value_ret = true;
                    }
                    /* the closest rax write to THIS ret was a byte write to al and
                     * was NOT zero/sign-extended (a movzx/mov eax would make
                     * last_rax_w >= 4): the bool-in-al contract. One such path is
                     * enough — the compiler only leaves al's upper bits stale when
                     * the callers read only al. */
                    if (last_rax_w == 1) {
                        if (eax_zeroed_before(ci, last_rax_idx)) saw_wide_ret = true;
                        else saw_byte_ret = true;
                    }
                    else if (last_rax_w >= 4) saw_wide_ret = true;
                }
            }
            /* tail call: jmp to a function start outside [f.rva, f.rva+size) */
            if (c.id == X86_INS_JMP && x.op_count == 1 &&
                x.operands[0].type == X86_OP_IMM) {
                uint64_t tgt = (uint64_t)x.operands[0].imm;
                bool inside = (tgt >= f.rva && tgt < f.rva + (f.size ? f.size : n));
                if (!inside) {
                    for (size_t g = 0; g < e->func_len; ++g)
                        if (e->funcs[g].rva == tgt) { tail_target = tgt; break; }
                }
                /* shared-epilogue return: `mov eax,<val>; jmp <forward, in-range>`
                 * sets the return value then branches to a common epilogue whose
                 * `ret` is far away in the linear layout, so the ret-proximity test
                 * above misses it and the function is mis-typed `void` with every
                 * `return <val>` dropped (map_put/vm_run/edit_distance/bfs_dist).
                 * A FORWARD in-range jmp with a just-set eax/xmm0 IS that idiom; a
                 * BACKWARD jmp is a loop back-edge (eax there is an accumulator). */
                else if (tgt > c.address && fwd_jmp_is_epilogue(tgt)) {
                    /* the just-set eax is a shared-epilogue RETURN value only if it
                     * is NOT consumed between its write and this jmp. A void early
                     * exit `mov eax,j; cmp i,eax; jne .; jmp epi` computes the
                     * `i==j` test THROUGH eax and leaves it dead — the jmp is a
                     * plain `return;`, not a value set (swap_ints/clamp_to/
                     * heap_sift_*). The genuine idiom (`mov eax,val; jmp epi`) has
                     * no intervening read of eax (nor an rax address use). */
                    bool rax_consumed = false;
                    for (long j = (last_rax_idx >= 0 ? last_rax_idx + 1 : (long)i);
                         j < (long)i && !rax_consumed; ++j) {
                        if (!ci[j].detail) continue;
                        cs_x86& cx = ci[j].detail->x86;
                        for (int o = 0; o < cx.op_count; ++o) {
                            const cs_x86_op& oo = cx.operands[o];
                            if (oo.type == X86_OP_REG && (oo.access & CS_AC_READ)) {
                                Reg rr; int rw; map_reg(oo.reg, rr, rw);
                                if (rr == R_RAX) { rax_consumed = true; break; }
                            } else if (oo.type == X86_OP_MEM) {
                                const x86_op_mem& mm = oo.mem; Reg ar; int aw;
                                if (mm.base  != X86_REG_INVALID) { map_reg(mm.base,  ar, aw); if (ar == R_RAX) { rax_consumed = true; break; } }
                                if (mm.index != X86_REG_INVALID) { map_reg(mm.index, ar, aw); if (ar == R_RAX) { rax_consumed = true; break; } }
                            }
                        }
                    }
                    if (!rax_consumed && last_rax_w > 0 && ((long)i - last_rax_idx) <= 4) {
                        if (last_rax_w > ret_rax_w) ret_rax_w = last_rax_w;
                        rax_live_at_ret = true;
                        if (last_rax_from_call) {
                            ret_only_from_call = true;
                            ret_call_target = last_rax_call_target;
                        } else {
                            saw_real_value_ret = true;
                        }
                        if (last_rax_w == 1) saw_byte_ret = true;
                        else if (last_rax_w >= 4) saw_wide_ret = true;
                    }
                    if (last_xmm0_idx >= 0 && ((long)i - last_xmm0_idx) <= 4) {
                        xmm0_live_at_ret = true;
                        int fw = last_xmm0_fw ? last_xmm0_fw : 4;
                        if (fw > ret_xmm0_w) ret_xmm0_w = fw;
                    }
                }
            }
            /* tail JMP through a FIXED IAT slot = a tail call to an IMPORT (the alloc
             * wrapper `... jmp qword ptr [HeapAlloc]`). The function returns the
             * import's value, which sits in the full 64-bit rax and is frequently a
             * POINTER/HANDLE — recover an 8-byte return so callers don't truncate it to
             * `int` (`(unsigned int)ptr`). Base register present => a vtable/computed
             * tail call, left alone. */
            if (c.id == X86_INS_JMP && x.op_count == 1 && x.operands[0].type == X86_OP_MEM &&
                (x.operands[0].mem.base == X86_REG_INVALID || x.operands[0].mem.base == X86_REG_RIP) &&
                x.operands[0].mem.index == X86_REG_INVALID) {
                if (ret_rax_w < 8) ret_rax_w = 8;
                saw_wide_ret = true; rax_live_at_ret = true;
            }
            /* a call sets rax to the callee's return value; remember its width
             * provisionally (a later explicit eax/rax write or a discard will
             * override). This lets `call f; ret` wrappers be non-void while a
             * void function that later overwrites or ignores rax stays void. */
            if (c.id == X86_INS_CALL) {
                saw_prior_call = true;   /* real work precedes any later tail jmp */
                /* width inherited from callee when known, else 4 (int default) */
                int cw = 4;
                bool callee_void = false;
                bool callee_float = false; int callee_fw = 4;
                if (c.detail && x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                    uint64_t ct = (uint64_t)x.operands[0].imm;
                    auto it = tab.find(ct);
                    if (it != tab.end()) {
                        if (it->second.ret_kind == 2) cw = 8;
                        else if (it->second.ret_kind == 0) callee_void = true;
                        else if (it->second.ret_kind == 3 || it->second.ret_kind == 4) {
                            callee_float = true;
                            callee_fw = (it->second.ret_kind == 4) ? 8 : 4;
                        }
                    }
                } else if (c.detail && x.op_count >= 1 && x.operands[0].type == X86_OP_MEM &&
                           (x.operands[0].mem.base == X86_REG_INVALID ||
                            x.operands[0].mem.base == X86_REG_RIP) &&
                           x.operands[0].mem.index == X86_REG_INVALID) {
                    /* indirect call through a FIXED IAT slot = an import (unlike a
                     * vtable call `[rax+0x20]`, which has a base register). Its return
                     * sits in the full 64-bit rax and is frequently a POINTER/HANDLE
                     * (HeapAlloc/VirtualAlloc/CreateFile...). Defaulting to 4 truncates
                     * a forwarded pointer at every caller — the alloc-wrapper
                     * `int fun_000866d0()` -> `(unsigned int)ptr` truncation bug. */
                    cw = 8;
                }
                if (callee_float) {
                    /* a FLOAT/DOUBLE-returning callee leaves its result in xmm0 (rax
                     * is left undefined by the ABI). A `call fp_helper; ret` wrapper
                     * therefore returns float, not the stale rax — the u2f-based
                     * bit-reinterpret builders (f_fabs/f_neg/f_copysign/f_rebuild/…)
                     * end in exactly this shape and were mis-typed `int`, truncating
                     * the returned float to an integer value. Record the xmm0 result
                     * so the ret-proximity test picks it as the return, and clear the
                     * rax-from-call provenance so rax cannot win the tiebreak. */
                    last_xmm0_idx = (long)i; last_xmm0_fw = callee_fw;
                    last_xmm0_packed = false;
                    last_rax_w = 0; last_rax_from_call = false;
                } else if (callee_void) {
                    /* a KNOWN-void callee leaves garbage in rax, not a return value.
                     * A loop/tail body ending in `call void_helper` (build_max_heap/
                     * heap_sort/comb_sort → heap_sift_down/swap_ints) must not be
                     * mis-typed as returning that garbage. A later real eax write on
                     * the ret path still overrides this. */
                    last_rax_w = 0; last_rax_from_call = false;
                } else {
                    last_rax_w = cw; last_rax_idx = (long)i; saw_call_result = true;
                    last_rax_from_call = true;
                    last_rax_call_target = 0;
                    if (c.detail && x.op_count >= 1) {
                        if (x.operands[0].type == X86_OP_IMM)
                            last_rax_call_target = (uint64_t)x.operands[0].imm;  /* direct call */
                        else if (x.operands[0].type == X86_OP_MEM &&
                                 x.operands[0].mem.index == X86_REG_INVALID) {
                            /* `call qword ptr [IAT]` -- an IMPORT. Recorded as the IAT SLOT rva,
                             * which is how e->imports keys them. Without this an import call
                             * recorded target 0 and a wrapper around an API could not be told
                             * from a wrapper around anything else, so the API's return type had
                             * nowhere to propagate from (the ret_api fixpoint below).
                             * An IAT slot lives in .idata and can never collide with a function
                             * rva, so the existing consumers (the void fixpoint, which looks the
                             * target up in `tab`) simply do not match it -- no behaviour change. */
                            const x86_op_mem& mm = x.operands[0].mem;
                            if (mm.base == X86_REG_RIP)
                                last_rax_call_target = c.address + c.size + (uint64_t)mm.disp;
                            else if (mm.base == X86_REG_INVALID)
                                last_rax_call_target = (uint64_t)mm.disp;
                        }
                    }
                }
            }
            /* idiv/div/imul/mul (1-operand forms) write the result to eax/rax
             * IMPLICITLY — capstone does not list eax as an operand, so the
             * explicit-operand scan below misses it and a function that returns a
             * division/multiplication result (e.g. fx_mean's `acc/count`) was
             * mis-detected as void, dropping the whole return. */
            if (c.id == X86_INS_IDIV || c.id == X86_INS_DIV || c.id == X86_INS_MUL ||
                (c.id == X86_INS_IMUL && x.op_count == 1)) {
                int dw = (x.op_count >= 1 && x.operands[0].size) ? x.operands[0].size : 4;
                if (dw < 4) dw = 4;
                last_rax_w = dw; last_rax_idx = (long)i;
            }
            /* track sub rsp for homing */
            if (c.id == X86_INS_SUB && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM) {
                Reg r; int w; map_reg(x.operands[0].reg, r, w);
                if (r == R_RSP) { fs = x.operands[1].imm; sub_done = true; }
            }
            /* param homing mov [rsp+k], argreg */
            if (c.id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_MEM && x.operands[1].type == X86_OP_REG) {
                const x86_op_mem& m = x.operands[0].mem;
                Reg base = R_NONE; int t;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
                Reg s; int sw; map_reg(x.operands[1].reg, s, sw);
                int pidx = (s==R_RCX)?0:(s==R_RDX)?1:(s==R_R8)?2:(s==R_R9)?3:-1;
                if (base == R_RSP && m.index == X86_REG_INVALID && pidx >= 0) {
                    int64_t expect = 8 + 8 * pidx;
                    if (m.disp == expect) {
                        used_arg[pidx] = true; homed_arg[pidx] = true;
                        if (!sub_done) homed_presub[pidx] = true;   /* va_start shape */
                    }
                }
            }
            /* A param that is FORWARDED to a callee (`f(int a){ return g(a); }`)
             * reaches the callee only through the ABI register, never as an explicit
             * read operand, so the operand scan misses it and the param count comes
             * out short (month_len's `y` forwarded to is_leap -> arg dropped at every
             * call site). On a direct call to an already-analyzed callee, the still-
             * incoming arg registers it consumes (its param_count, minus any written
             * here) ARE used params of THIS function. */
            if (c.id == X86_INS_CALL && x.op_count >= 1 &&
                x.operands[0].type == X86_OP_IMM) {
                uint64_t ctgt = (uint64_t)x.operands[0].imm;
                auto cit = tab.find(ctgt);
                if (cit != tab.end()) {
                    int cpc = cit->second.param_count; if (cpc > 4) cpc = 4;
                    for (int p = 0; p < cpc; ++p)
                        if (!seen_write[p]) used_arg[p] = true;
                }
            }
            /* Same forwarding through an INDIRECT call to a KNOWN import (`call
             * qword ptr [IAT]`): a wrapper that forwards a param UNCHANGED into an
             * API arg (fun_0000c0b0 forwards a3=r8 into a logging call's r8) never
             * reads that reg as an explicit operand, so the IMM rule above misses
             * it and the wrapper's arity comes out short — every call site then
             * DROPS the forwarded arg. Resolve the IAT slot; if it is a recognized
             * API, mark its arg registers (up to the known arity, minus any this
             * wrapper wrote itself) as used. Gated to a KNOWN import so an unknown
             * callee's arity can never over-count a genuinely-local arg reg. */
            if (c.id == X86_INS_CALL && x.op_count >= 1 &&
                x.operands[0].type == X86_OP_MEM) {
                const x86_op_mem& cm = x.operands[0].mem;
                uint64_t iat = 0; bool have_iat = false;
                if (cm.base == X86_REG_RIP && cm.index == X86_REG_INVALID) {
                    iat = c.address + c.size + (uint64_t)cm.disp; have_iat = true;
                } else if (cm.base == X86_REG_INVALID && cm.index == X86_REG_INVALID) {
                    iat = (uint64_t)cm.disp;
                    if (e->base && iat >= e->base) iat -= e->base;
                    have_iat = true;
                }
                if (have_iat) {
                    std::string inm;
                    for (size_t k = 0; k < e->import_len; ++k)
                        if (e->imports[k].iat_rva == iat && e->imports[k].name[0]) {
                            inm = e->imports[k].name; break;
                        }
                    int aargc, ark;
                    if (!inm.empty() && Decompiler::known_api(inm, aargc, ark)) {
                        int cpc = aargc; if (cpc > 4) cpc = 4;
                        for (int p = 0; p < cpc; ++p)
                            if (!seen_write[p]) used_arg[p] = true;
                    }
                }
            }
            /* LOCK RECOVERY: tally this function's callees so the sig assembly below
             * can tell a bare lock WRAPPER from a function that merely takes a lock.
             * Both shapes are resolved: a `call qword ptr [IAT]` to the API (the CRT
             * __acrt_lock idiom) and a `jmp qword ptr [IAT]` j_ import thunk. Read
             * only — the arity/return rules above are untouched. */
            if (c.id == X86_INS_CALL) ++lk_calls;
            if (c.id == X86_INS_CALL && x.op_count >= 1 &&
                x.operands[0].type == X86_OP_IMM) {
                lk_local = (uint64_t)x.operands[0].imm; ++lk_local_calls;
            }
            if ((c.id == X86_INS_CALL || c.id == X86_INS_JMP) && x.op_count >= 1 &&
                x.operands[0].type == X86_OP_MEM) {
                const x86_op_mem& lm = x.operands[0].mem;
                uint64_t liat = 0; bool lhave = false;
                if (lm.base == X86_REG_RIP && lm.index == X86_REG_INVALID) {
                    liat = c.address + c.size + (uint64_t)lm.disp; lhave = true;
                } else if (lm.base == X86_REG_INVALID && lm.index == X86_REG_INVALID) {
                    liat = (uint64_t)lm.disp;
                    if (e->base && liat >= e->base) liat -= e->base;
                    lhave = true;
                }
                if (lhave) {
                    for (size_t k = 0; k < e->import_len; ++k)
                        if (e->imports[k].iat_rva == liat && e->imports[k].name[0]) {
                            int lk = Decompiler::lock_api_kind(e->imports[k].name);
                            if (lk) {
                                if (c.id == X86_INS_CALL) { lk_api = lk; ++lk_api_calls; }
                                else lk_tail_api = lk;
                            }
                            break;
                        }
                }
            }
            /* A TAIL-CALL thunk (`… jmp target`) forwards its incoming args to the
             * target; the arg registers the target consumes that this thunk did NOT
             * set locally are this thunk's OWN params (fun_0005c660: rcx forwarded to
             * sub_5bf90 => a1, fixing the `in_RCX` leak). Also inherit the target's
             * RETURN type — a tail-call thunk returns exactly what its target does. */
            if (c.id == X86_INS_JMP && x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                uint64_t jt = (uint64_t)x.operands[0].imm;
                bool inside = (jt >= f.rva && jt < f.rva + (f.size ? f.size : n));
                if (!inside) {
                    auto jit = tab.find(jt);
                    if (jit != tab.end()) {
                        int cpc = jit->second.param_count; if (cpc > 4) cpc = 4;
                        for (int p = 0; p < cpc; ++p)
                            if (!seen_write[p]) used_arg[p] = true;
                        /* only a PURE forwarder (`return g()`) inherits an INTEGER
                         * target's return type; a function that did real work + a
                         * discarded call before its tail jmp is a void sequencer
                         * (Ghidra models `call; call; ret`). A float (xmm0) return is
                         * the exception — it is essentially always the real result. */
                        int trk = jit->second.ret_kind;
                        bool trk_float = (trk == 3 || trk == 4);
                        if (trk != 0 && !writes_eax && !writes_rax &&
                            (!saw_prior_call || trk_float))
                            tail_ret_inherit = trk;
                    }
                }
            }
            /* `xorps/xorpd/pxor xmm,xmm` (same reg) is the zero idiom: a pure define,
             * not a read of the xmm's incoming (param) value. */
            bool self_xor_fp = (c.id==X86_INS_XORPS||c.id==X86_INS_XORPD||c.id==X86_INS_PXOR)
                && x.op_count>=2 && x.operands[0].type==X86_OP_REG &&
                x.operands[1].type==X86_OP_REG && x.operands[0].reg==x.operands[1].reg;
            /* self-zeroing idiom (`xor r,r` / `sub r,r`) DEFINES the reg to 0 — its
             * operand reads are not a use of the incoming (param) value. */
            bool self_zero_gp = (c.id==X86_INS_XOR || c.id==X86_INS_SUB) &&
                x.op_count==2 && x.operands[0].type==X86_OP_REG &&
                x.operands[1].type==X86_OP_REG && x.operands[0].reg==x.operands[1].reg;
            /* any read of arg register before its first write => used */
            for (int k = 0; k < x.op_count && k < 8; ++k) {
                const cs_x86_op& op = x.operands[k];
                if (op.type == X86_OP_REG) {
                    Reg r; int w; map_reg(op.reg, r, w);
                    int pidx = (r==R_RCX)?0:(r==R_RDX)?1:(r==R_R8)?2:(r==R_R9)?3:-1;
                    /* Exclude operand-0 only when it is WRITE-ONLY (`mov r9d,x` — its
                     * prior value is discarded) or a self-zero. A READ-MODIFY-WRITE
                     * dst (`or r9d,[mem]`, `add`, `and`) READS the incoming value, so
                     * it IS a param use — missing it dropped arg4 of every 4-arg
                     * callee that consumes r9 via `or r9d,[g]` (fun_00015920, called
                     * with 3 of 4 args). */
                    bool is_dst0 = (k == 0 && (op.access & CS_AC_WRITE) &&
                                    (!(op.access & CS_AC_READ) || self_zero_gp));
                    if (pidx >= 0 && !seen_write[pidx] && !is_dst0)
                        used_arg[pidx] = true;
                    if (pidx >= 0 && (op.access & CS_AC_WRITE)) seen_write[pidx] = true;
                    /* XMM float/double argument: xmm0-3 read before written. A
                     * REPLACING op (movss/cvt*) on the dst discards its prior value
                     * (capstone READ is upper-bits preservation only), so it is not a
                     * param use; a read-modify-write (mulsd/addsd/...) dst read IS. */
                    int xp = (r>=R_XMM0 && r<=R_XMM3) ? (int)(r - R_XMM0) : -1;
                    if (xp >= 0) {
                        bool fp_dst = self_xor_fp ||
                            (k == 0 && (op.access & CS_AC_WRITE) && Decompiler::fp_def_only(c.id));
                        if ((op.access & CS_AC_READ) && !xmm_seen_write[xp] && !fp_dst) {
                            xmm_used[xp] = true;
                            /* MAX-wins width: a param used by ANY double-width scalar op
                             * (sqrtsd/addsd/movsd) is a double — first-wins wrongly locked
                             * `float` when a movss/cvt read preceded the real double op. */
                            int fw = fp_scalar_width(c.id); if (fw > xmm_w[xp]) xmm_w[xp] = fw;
                        }
                        if (op.access & CS_AC_WRITE) xmm_seen_write[xp] = true;
                    }
                    if (r == R_RAX && (op.access & CS_AC_WRITE)) {
                        if (w >= 8) writes_rax = true; else writes_eax = true;
                        last_rax_w = w; last_rax_idx = (long)i;
                        last_rax_from_call = false;
                        /* a LONE `mov rax, argreg` never rewritten = the return-the-
                         * param idiom (memcpy/memmove/strcpy return dst); a 2nd rax
                         * write disqualifies it. */
                        ++rax_write_count;
                        if (rax_write_count == 1 && c.id == X86_INS_MOV && x.op_count == 2 &&
                            x.operands[1].type == X86_OP_REG) {
                            Reg sr; int sw2; map_reg(x.operands[1].reg, sr, sw2);
                            rax_param_copy = (sr==R_RCX)?0:(sr==R_RDX)?1:(sr==R_R8)?2:(sr==R_R9)?3:-1;
                        } else rax_param_copy = -1;
                    }
                    /* the CALL result in rax consumed at 64-bit width (`test rax,rax`,
                     * `mov r64,rax`, `cmp rax,..`) proves the callee returned a 64-bit
                     * value (pointer/long long), even if its own sig came out `int` —
                     * so a `call f; test rax,rax; ...; ret` wrapper isn't truncated to
                     * int (the fun_0005dc00 allocator chain). */
                    else if (r == R_RAX && (op.access & CS_AC_READ) && w >= 8 &&
                             last_rax_from_call && last_rax_idx >= 0 && last_rax_idx < (long)i) {
                        last_rax_w = 8;
                    }
                    if (r == R_XMM0 && (op.access & CS_AC_WRITE)) {
                        last_xmm0_idx = (long)i;
                        /* prefer the tracked xmm0 width (captures a `movaps xmm0,xmmN`
                         * copy of a double value), else this op's own FP width. */
                        int fw = xmm_fw[0] ? xmm_fw[0] : fp_scalar_width(c.id);
                        if (fw) last_xmm0_fw = fw;
                        /* a PACKED 128-bit move into xmm0 carrying NO scalar-FP width is
                         * a memcpy/memmove vector copy (`movdqu xmm0,[rdx]`), not a float
                         * return — a pointer-returning routine (`mov rax,rcx; ...; ret`)
                         * whose xmm0 is only copy scratch must not be typed float. */
                        last_xmm0_packed = (fw == 0) &&
                            (c.id==X86_INS_MOVDQU || c.id==X86_INS_MOVDQA ||
                             c.id==X86_INS_MOVUPS || c.id==X86_INS_MOVAPS ||
                             c.id==X86_INS_MOVUPD || c.id==X86_INS_MOVAPD);
                    }
                }
                if (op.type == X86_OP_MEM) {
                    const x86_op_mem& m = op.mem;
                    Reg bi[2] = {R_NONE, R_NONE}; int t;
                    if (m.base != X86_REG_INVALID) map_reg(m.base, bi[0], t);
                    if (m.index != X86_REG_INVALID) map_reg(m.index, bi[1], t);
                    for (Reg r : bi) {
                        int pidx=(r==R_RCX)?0:(r==R_RDX)?1:(r==R_R8)?2:(r==R_R9)?3:-1;
                        if (pidx >= 0 && !seen_write[pidx]) used_arg[pidx] = true;
                    }
                    /* the BASE (not index) of a REAL memory access — a load/store, never a
                     * plain LEA address-calc whose result may be an integer — proves the arg
                     * is a pointer. An index register is a scaled offset (often an int), so
                     * it does not count. First-seen access width is the pointee hint. */
                    {
                        int pb=(bi[0]==R_RCX)?0:(bi[0]==R_RDX)?1:(bi[0]==R_R8)?2:(bi[0]==R_R9)?3:-1;
                        if (pb >= 0 && !seen_write[pb] && c.id != X86_INS_LEA &&
                            c.id != X86_INS_NOP) {
                            arg_is_ptr[pb] = true;
                            if (arg_ptr_w[pb] == 0 && op.size > 0) arg_ptr_w[pb] = op.size;
                        }
                    }
                    /* stack-passed argument (5th+): read from the caller's arg area
                     * at [rsp + frame + 0x28 + 8*(k-5)] under /Od. A slot only
                     * counts as an INCOMING arg if it is read BEFORE the callee
                     * writes it; a slot the callee writes first is its own spill
                     * or local (e.g. `movaps [rsp+0x30], xmm6` saving a callee-
                     * saved register), and must not inflate the param count — that
                     * is what produced phantom trailing args (v1,v13,v12) in every
                     * caller. Keyed on the raw disp so a spill's store and reload
                     * match regardless of frame-offset/push accuracy. */
                    if (bi[0] == R_RSP && m.index == X86_REG_INVALID) {
                        int64_t rel = (int64_t)m.disp - fs;
                        bool is_w = (op.access & CS_AC_WRITE) != 0;
                        bool is_r = (op.access & CS_AC_READ)  != 0;
                        if (rel >= 0x28 && (rel % 8) == 0) {
                            int k = (int)(rel / 8);
                            if (is_r && !stk_written.count(m.disp) &&
                                k >= 5 && k <= 32 && k > max_stack_arg)
                                max_stack_arg = k;
                        }
                        if (is_w) stk_written.insert(m.disp);
                    }
                }
            }
            /* a CALL clobbers volatile xmm0-5: a subsequent xmm0-3 read is the
             * call's float RESULT, not an incoming param. */
            if (c.id == X86_INS_CALL)
                for (int p = 0; p < 4; ++p) xmm_seen_write[p] = true;
            (void)fs; (void)sub_done;
        }
        cs_free(ci, count);

        /* Prefer the prologue homing stores (the reliable /Od param signal):
         * the highest contiguous homed arg index is the parameter count. Only
         * when nothing is homed do we fall back to the read-before-write
         * heuristic (which can over-count scratch uses of rdx/r8). */
        /* VARIADIC: all four integer arg registers homed to shadow space before the frame
         * exists. See homed_presub. This is what lets a caller trust a format string's arity
         * even when the string has NO conversions -- `f("hello")` passes exactly one argument,
         * but nothing in the machine code says so, and the engine otherwise assumes all four
         * arg registers are live and prints the residue:
         *     fun_00001310("[NullWare] Waiting for VALORANT...\n", 0, 4, 0)
         * See trim_format_args. */
        sig.is_variadic = homed_presub[0] && homed_presub[1] &&
                          homed_presub[2] && homed_presub[3];
        bool any_home = homed_arg[0]||homed_arg[1]||homed_arg[2]||homed_arg[3];
        int pc = 0;
        if (any_home) {
            /* The HIGHEST homed arg index sets the count: the Win64 ABI fills the
             * arg registers left-to-right, so a homed arg-N implies args 0..N all
             * exist even when a LOWER one was used directly from its register with
             * no home store (an /O2 callee that spills rdx to its home slot but
             * dereferences rcx in place: `mov [rsp+0x10],edx; ... [rcx+off]`). The
             * old contiguous-from-0 scan stopped at the first un-homed slot and
             * returned 0 params for such `f(rcx,rdx)` functions — so EVERY argument
             * was dropped at each call site (fun_00012370 called `()`, fun_00015920
             * called with 3 of 4 args). */
            for (int p = 0; p < 4; ++p) if (homed_arg[p]) pc = p + 1;
        } else {
            /* HIGHEST read-before-write arg reg + 1 = param count. The Win64 ABI
             * fills arg registers left-to-right, so a callee that reads arg N as a
             * param means the caller passed args 0..N — even when a LOWER slot is
             * unused (a DllMain-style `f(hinst, reason)` that ignores hinst/rcx but
             * reads reason/edx: the old leading-gap `break` returned 0 params, so
             * every call site dropped ALL args). Float (xmm) positions count too. */
            int maxu = -1;
            for (int p = 0; p < 4; ++p)
                if (used_arg[p] || xmm_used[p]) maxu = p;
            pc = maxu + 1;
        }
        /* Fold in XMM float/double params: a position is a float arg when xmm[p] is
         * read before write and the integer reg at that position is NOT a param. The
         * highest float position extends the count (ABI assigns positions by index),
         * so a homed `f(int a1, double a2)` recovers 2 params with a2 from xmm1. */
        unsigned char fmask = 0, dmask = 0, tmask = 0;
        for (int p = 0; p < 4; ++p)
            if (xmm_used[p] && !used_arg[p] && !homed_arg[p]) {
                fmask |= (unsigned char)(1u << p);
                if (xmm_w[p] == 8) dmask |= (unsigned char)(1u << p);            /* movsd => double */
                if (xmm_w[p] == 4 || xmm_w[p] == 8) tmask |= (unsigned char)(1u << p); /* width known */
            }
        for (int p = 3; p >= 0; --p)
            if (fmask & (1u << p)) { if (p + 1 > pc) pc = p + 1; break; }
        sig.float_mask = fmask;
        sig.double_mask = dmask;
        sig.float_typed_mask = tmask;
        if (max_stack_arg > pc) pc = max_stack_arg;   /* args 5+ passed on stack */
        sig.param_count = pc;
        /* POINTER PARAMS: an arg reg dereferenced before written is a pointer. Exclude
         * float positions (those args arrive in xmm, so an arg-reg deref there is a
         * different value) and positions beyond the recovered arity. */
        for (int p = 0; p < 4 && p < pc; ++p)
            if (arg_is_ptr[p] && !(fmask & (1u << p))) {
                sig.ptr_param_mask |= (unsigned char)(1u << p);
                sig.ptr_param_w[p] = (unsigned char)(arg_ptr_w[p] ? arg_ptr_w[p] : 8);
            }
        if (!has_ret) sig.ret_kind = 0;
        /* a STRONG float return (`cvt/fp-op xmm0; ret` on some path) beats an
         * incidental rax from a tail `call err(); ret` (a noreturn error path whose
         * rax is never a real return) — fun_00068420 is a float fmod-like helper
         * mis-typed `int` because its __invalid_parameter tail set rax_live. */
        else if (xmm0_live_at_ret && saw_fp_ret_tail) sig.ret_kind = (ret_xmm0_w >= 8) ? 4 : 3;
        else if (rax_live_at_ret) sig.ret_kind = (ret_rax_w >= 8) ? 2 : 1;
        else if (xmm0_live_at_ret) sig.ret_kind = (ret_xmm0_w >= 8) ? 4 : 3; /* float/double */
        /* x87 ST(0) return (32-bit /arch:IA32). Deliberately ranked BELOW the rax test:
         * the depth tracking can only fail to notice a return, never invent one over a
         * real integer return. */
        else if (x87_live_at_ret) sig.ret_kind = (x87_ret_w >= 8) ? 4 : 3;
        else if (tail_ret_inherit) sig.ret_kind = tail_ret_inherit;  /* tail-call thunk returns its target's value */
        else if (rax_param_copy >= 0) sig.ret_kind = 2;  /* lone `mov rax,argreg` = returns that pointer (memcpy dst) */
        else sig.ret_kind = 0;                       /* void */
        /* byte (bool/char) return: a ret leaves only al meaningful and the value
         * is a small int (kind 1, not ll/float). Fixes `xor al,al; ret` rendering
         * as `return (X & -256)` instead of `return 0`. */
        /* Byte return only when NO ret path leaves a full eax/rax value: a function
         * with any `mov eax,imm` / `xor eax,eax` / wide return is `int` even if some
         * other path uses `setcc al` (an int-returning predicate). Requiring no wide
         * ret path stops `int seg_intersect(){...}` rendering as `unsigned char`. */
        if (rax_live_at_ret && sig.ret_kind == 1 && saw_byte_ret && !saw_wide_ret)
            sig.ret_byte = true;
        sig.ret_only_from_call = ret_only_from_call;
        sig.saw_real_value_ret = saw_real_value_ret;
        sig.saw_prior_call = saw_prior_call;
        sig.ret_call_target = ret_call_target;
        /* NORETURN. Three conditions, all required:
         *   no `ret` anywhere      -- it never hands control back
         *   no tail JMP out        -- a tail call CAN return; that is a thunk, not a trap
         *   the range ENDS IN A TRAP (int3/ud2) -- the guard that makes this safe. "No ret"
         *     alone is ALSO what a function with wrong bounds looks like, and calling that
         *     noreturn would DELETE LIVE CODE at every caller. Costs nothing: all 12 real
         *     candidates in NullWare end in int3 (verified: 0x5e60, 0x5ef0, 0x74590, ...). */
        sig.is_noreturn = !has_ret && !tail_target &&
                          (last_id == X86_INS_INT3 || last_id == X86_INS_UD2);
        /* LOCK RECOVERY: only a TINY one-call body is the lock primitive itself.
         * Without the size guard a real function whose single call happens to be
         * `__acrt_lock(n)` would be tagged an acquire thunk, and every one of ITS
         * callers would then report a guarded region that does not exist — the
         * annotation must never claim a lock the code does not take. */
        if (count <= 24) {
            if (lk_calls == 1 && lk_api_calls == 1) sig.lock_kind = lk_api;
            else if (lk_calls == 0 && lk_tail_api) sig.lock_kind = lk_tail_api;
            else if (lk_calls == 1 && lk_local_calls == 1) lock_thunk_of[f.rva] = lk_local;
            else if (lk_calls == 0 && tail_target) lock_thunk_of[f.rva] = tail_target;
        }
        tab[f.rva] = sig;
        if (tail_target) {
            tail_of[f.rva] = tail_target;
            /* A tail thunk that never wrote an arg register forwards rcx/rdx/r8/r9
             * to the target UNCHANGED, so its true arity is the target's — recorded
             * for the fixpoint below (the inline inheritance at the JMP handler only
             * fires when the target was already analyzed; a thunk at a HIGHER rva
             * than its target, or a chain, needs the order-independent pass). A
             * function that rearranges args (`mov rcx,rdx; jmp t`) wrote an arg reg
             * and is excluded — its arity comes from its own body. */
            if (!seen_write[0] && !seen_write[1] && !seen_write[2] && !seen_write[3])
                fwd_thunk_of[f.rva] = tail_target;
        }
        (void)writes_eax; (void)writes_rax; (void)saw_call_result;
    }
    cs_close(&h);

    /* Resolve tail-call return kinds: a function ending in `jmp <callee>` returns
     * whatever the callee returns. Iterate to a fixed point over the tail chain. */
    for (int iter = 0; iter < 4; ++iter) {
        for (auto& kv : tail_of) {
            uint64_t fr = kv.first, callee = kv.second;
            if (!tab.count(fr) || !tab.count(callee)) continue;
            FuncSig& s = tab[fr];
            if (s.ret_kind == 0 && tab[callee].ret_kind != 0) {
                int ck = tab[callee].ret_kind;
                bool ck_float = (ck == 3 || ck == 4);
                /* A float (xmm0) tail-return is essentially always the meaningful
                 * result, so forward it even after prior work (`mean=f(); return
                 * sqrt(v)`). An integer/pointer tail-return after a discarded prior
                 * call is a void sequencer's goto — do NOT invent a return value. */
                if (!s.saw_prior_call || ck_float) s.ret_kind = ck;
            }
        }
        /* Propagate ARITY along the pure-forwarding-thunk chain to a fixed point:
         * fun_0001d010 = `jmp fun_0001c790` was declared void()/called with 0 args
         * at every site because a jmp-only body reads no arg registers. A forwarding
         * thunk's arity IS its target's. */
        /* Propagate the lock kind along the wrapper chain (thunk-of-thunk): 4
         * iterations, matching the arity/return chains above. */
        for (auto& kv : lock_thunk_of) {
            uint64_t fr = kv.first, callee = kv.second;
            if (!tab.count(fr) || !tab.count(callee)) continue;
            if (tab[callee].lock_kind && !tab[fr].lock_kind)
                tab[fr].lock_kind = tab[callee].lock_kind;
        }
        for (auto& kv : fwd_thunk_of) {
            uint64_t fr = kv.first, callee = kv.second;
            if (!tab.count(fr) || !tab.count(callee)) continue;
            FuncSig& s = tab[fr];
            if (tab[callee].param_count > s.param_count) {
                s.param_count = tab[callee].param_count;
                s.float_mask = tab[callee].float_mask;
                s.double_mask = tab[callee].double_mask;
                s.float_typed_mask = tab[callee].float_typed_mask;
                s.ptr_param_mask = tab[callee].ptr_param_mask;
                for (int p = 0; p < 4; ++p) s.ptr_param_w[p] = tab[callee].ptr_param_w[p];
            }
        }
    }

    /* Void fixpoint: a function whose ONLY return evidence is a raw SELF-recursive
     * call result (`... = self(); return`), never a deliberate const/computed/
     * loaded base case, is void — a pure self-recursion with no base value
     * (quicksort_range, heapify). Restricted to self-recursion: the callee-void
     * cascade was unsafe because `saw_real_value_ret` under-detects value returns
     * that reach the ret through a far shared-epilogue load (distinct_bytes
     * `return count`), and would wrongly void them. A genuine recursive int
     * (factorial `return 1`, gcd `return a`) records a real value return here. */
    for (auto& kv : tab) {
        FuncSig& s = kv.second;
        if (s.ret_kind == 0 || !s.ret_only_from_call || s.saw_real_value_ret)
            continue;
        if (s.ret_call_target == kv.first) s.ret_kind = 0;
    }

    /* CROSS-FUNCTION RETURN TYPE, to a fixpoint over the call graph.
     *
     * propagate_api_types only sees a DIRECT API call, so it recovers
     *     HMODULE v2 = GetModuleHandleW(..)
     * and is blind the moment the program wraps it, which real code always does:
     *     HMODULE GetDllBase(void)  { return GetModuleHandleW(L".."); }
     *     HMODULE dll = GetDllBase();      <- the caller never sees GetModuleHandleW
     * A function whose result IS an API's result RETURNS that API's type; a function whose
     * result is THAT function's result returns it too. Seeded from the imports, then iterated
     * so wrappers-of-wrappers inherit. Bounded to 8 rounds: the call graph can contain cycles
     * and this must terminate regardless.
     *
     * Sound because ret_call_target is only set when the return value came from that call --
     * `ret_only_from_call && !saw_real_value_ret` means no path returns a deliberate value of
     * its own. A function that sometimes returns a handle and sometimes an error code has
     * saw_real_value_ret and is left alone.
     * NOTE: measured ZERO sites on NullWare (no local fn there returns an API result), so the
     * gate binary cannot validate this -- _qa/fixtures/features/feat_c.c f_get_base/f_use_base is the
     * oracle. DS_NO_APITYPES. */
    if (!std::getenv("DS_NO_APITYPES")) {
        /* seed: ret_call_target is an IAT slot whose API has a known return type */
        for (auto& kv : tab) {
            FuncSig& s = kv.second;
            if (!s.ret_call_target || !s.ret_only_from_call || s.saw_real_value_ret) continue;
            for (size_t i = 0; i < e->import_len; ++i) {
                if (e->imports[i].iat_rva != s.ret_call_target || !e->imports[i].name[0]) continue;
                std::string t = Decompiler::api_ret_type(e->imports[i].name);
                if (!t.empty()) s.ret_api = t;
                break;
            }
        }
        /* iterate: a wrapper inherits from the local function it returns */
        for (int round = 0; round < 8; ++round) {
            bool changed = false;
            for (auto& kv : tab) {
                FuncSig& s = kv.second;
                if (!s.ret_api.empty() || !s.ret_call_target ||
                    !s.ret_only_from_call || s.saw_real_value_ret) continue;
                if (s.ret_call_target == kv.first) continue;      /* self-recursion */
                auto t = tab.find(s.ret_call_target);
                if (t != tab.end() && !t->second.ret_api.empty()) {
                    s.ret_api = t->second.ret_api; changed = true;
                }
            }
            /* ...and through a TAIL-CALL THUNK, which has no `call` to hang ret_call_target on:
             *     f_get_base2:  jmp f_get_base        <- one instruction, no call, no ret
             * A thunk returns EXACTLY what its target returns, by definition -- it does not
             * even have a frame to alter it in. tail_of already holds these pairs. */
            for (auto& kv : tail_of) {
                auto s = tab.find(kv.first);
                auto t = tab.find(kv.second);
                if (s == tab.end() || t == tab.end()) continue;
                if (!s->second.ret_api.empty() || t->second.ret_api.empty()) continue;
                s->second.ret_api = t->second.ret_api; changed = true;
            }
            if (!changed) break;
        }
    }
}

} /* anonymous namespace */

/* ====================================================================== */
/*  Public entry point                                                     */
/* ====================================================================== */

extern "C" char* ds_decompile(ds_engine* e, uint64_t func_rva) {
    if (!e) return nullptr;
    const ds_func* f = nullptr;
    for (size_t i = 0; i < e->func_len; ++i) {
        if (e->funcs[i].rva == func_rva) { f = &e->funcs[i]; break; }
    }
    if (!f) return nullptr;

    std::string result;
    try {
        /* CACHE THE SIG TABLE PER ENGINE. build_sig_table scans EVERY function (prologue
         * disasm, call-graph fixpoints), so calling it once per ds_decompile makes a whole-DLL
         * dump O(functions^2) -- measured 2 fns/s on ntdll (4598 fns), a full dump ~40 min. The
         * table is a pure function of the engine's (unchanging) function set, so it is computed
         * ONCE per engine and reused. Keyed by (engine, func_len) so a rebuilt/extended engine
         * recomputes. Mutex-guarded: the dump tool decompiles across N threads.
         * DS_NO_SIGCACHE forces the old per-call build (for A/B). */
        static std::mutex sc_mtx;
        static std::map<ds_engine*, std::pair<size_t, std::shared_ptr<std::map<uint64_t,FuncSig>>>> sc;
        std::shared_ptr<std::map<uint64_t, FuncSig>> sig;
        if (std::getenv("DS_NO_SIGCACHE")) {
            sig = std::make_shared<std::map<uint64_t, FuncSig>>();
            build_sig_table(e, *sig);
        } else {
            std::lock_guard<std::mutex> lk(sc_mtx);
            auto it = sc.find(e);
            if (it != sc.end() && it->second.first == e->func_len) {
                sig = it->second.second;
            } else {
                sig = std::make_shared<std::map<uint64_t, FuncSig>>();
                build_sig_table(e, *sig);
                sc[e] = {e->func_len, sig};
            }
        }
        Decompiler dc(e, f, sig.get());
        result = dc.run();
    } catch (...) {
        std::string fname = (f->name[0] ? sani(std::string(f->name))
                                        : "sub_" + std::to_string(func_rva));
        result = "/* decompilation failed: exception */\nvoid " +
                 fname + "(void) {\n}\n";
    }
    return dup_to_c(result);
}

#endif /* DS_USE_CAPSTONE */
