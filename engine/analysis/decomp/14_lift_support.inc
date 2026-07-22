/* 14_lift_support.inc -- lifter support: rsp, calls, stores, misc
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Extend a value read at source width `sw` to destination width `dw`, either
     * zero- (uns=true) or sign- (uns=false) extended. Produces a value of width
     * dw with minimal casts. */
    ExprP ext_to(ExprP v, int sw, int dw, bool uns) {
        if (dw < 4) dw = 4;   /* sub-dword dests still occupy >=int in C */
        if (v->kind == EK::Const) {
            int64_t cv = v->cval;
            uint64_t um;
            int64_t sm;
            if (sw == 1) { um = cv & 0xFF; sm = (int8_t)cv; }
            else if (sw == 2) { um = cv & 0xFFFF; sm = (int16_t)cv; }
            else { um = (uint32_t)cv; sm = (int32_t)cv; }
            return uns ? mkConst((int64_t)um, dw, true) : mkConst(sm, dw, false);
        }
        /* If the value is already a typed read of width sw, a single cast to the
         * destination type captures the extension when the source value's own
         * width matches sw. We cast to (signed/unsigned) of width sw first to
         * fix the source interpretation, then the C usual conversions widen. To
         * keep it minimal we collapse to one cast when sw>=4. */
        if (sw >= 4) {
            return mkCast(cast_str(dw, uns), v, dw, uns);
        }
        /* Narrow source (byte/word). The result MUST be a width-dw value so later
         * reads observe the extended quantity, not a narrow memory access. If the
         * value is already a typed read of the source width with matching sign, a
         * single dest-width cast suffices: (int)*(signed char*)p. Otherwise fix
         * the source sign first, then widen. */
        bool src_ok = (v->width == sw) &&
                      (v->kind == EK::Mem || v->kind == EK::Var) &&
                      (v->is_unsigned == uns);
        if (src_ok)
            return mkCast(cast_str(dw, uns), v, dw, uns);
        ExprP narrow = mkCast(cast_str(sw, uns), v, sw, uns);
        return mkCast(cast_str(dw, uns), narrow, dw, uns);
    }

    void arith2(Block& b, const cs_x86& x, const std::string& op, uint64_t addr,
                bool unsigned_shift = false) {
        if (x.op_count < 2) return;
        const cs_x86_op& d = x.operands[0];
        const cs_x86_op& s = x.operands[1];
        int w = d.size ? d.size : 4;
        ExprP lhs = rvalue(d);
        ExprP rhs = norm_shift_count(rvalue(s));
        bool uns = unsigned_shift;
        /* A LOGICAL right shift (shr) reads its operand ZERO-extended. For an 8/16-
         * bit sub-register, rvalue() returns a SIGNED narrowing (`(short)x` /
         * `(signed char)x`) which, when C promotes it to int for the shift, SIGN-
         * extends — so `movzx edi,ax; shr di,0xf` (extract bit 15) mis-rendered as
         * `(unsigned int)((short)ax) >> 15`, giving 0xFFFF for ax=0x8000 instead of
         * 1. Re-cast the operand UNSIGNED at the sub-register width so the high bits
         * are zero. Only for logical shifts and sub-int widths; wider/signed shifts
         * are unchanged. */
        if (unsigned_shift && w < 4 && lhs) {
            if (lhs->kind == EK::Cast && lhs->a && lhs->width == w)
                lhs = mkCast(cast_str(w, true), clone(lhs->a), w, true);
            else
                lhs = mkCast(cast_str(w, true), lhs, w, true);
        }
        /* A wide (64-bit) MULTIPLY of narrower operands must widen one operand so the
         * C product is 64-bit: `(unsigned int)a * (unsigned int)b` is a 32-bit product
         * reduced mod 2^32, dropping the high half — which corrupts every bignum limb
         * multiply whose outgoing carry is `product >> 32` (always 0 if truncated).
         * The 3-operand imul path already widens; the 2-operand `imul r11,rax` (this
         * path) did not. */
        if (op == "*" && w >= 8) {
            int lw = lhs && lhs->width ? lhs->width : 4;
            int rw = rhs && rhs->width ? rhs->width : 4;
            if (lhs && lw < 8)      lhs = ext_to(lhs, lw, 8, lhs->is_unsigned);
            else if (rhs && rw < 8) rhs = ext_to(rhs, rw, 8, rhs->is_unsigned);
        }
        ExprP res = mkBinary(op, lhs, rhs, w, uns);
        do_dst(b, d, res, addr);
        set_flags_dst(d, res, w);
    }

    /* The shift count of a variable shift comes from CL (8-bit), which the lifter
     * wraps in a narrowing `(signed char)`/`(unsigned char)` cast. C promotes
     * the shift count to int anyway, so that cast is pure noise — strip it so we
     * emit `x << n` / `x >> (32 - n)` instead of `x << (signed char)n`. */
    ExprP norm_shift_count(const ExprP& cnt) {
        ExprP c = cnt;
        while (c && c->kind == EK::Cast && c->a &&
               (c->width == 1 || c->width == 2)) {
            c = c->a;
        }
        return c ? c : cnt;
    }

    /* SAR dst, imm.  A signed arithmetic right shift by a constant is the
     * compiler's lowering of `x / (1<<k)` for a power-of-two divisor when the
     * sign-correction has already been applied (MSVC /Od emits
     *   tmp = x + (x >>u (W-1));  result = tmp SAR k
     * for k==1, or  x + ((x SAR (W-1)) >>u (W-k))  in general).  We must NOT
     * render that as `>>` because signed `/` rounds toward zero whereas `>>`
     * rounds toward -inf; they differ for negatives.  Detect the
     * sign-bias-then-shift shape and re-emit it as `/ (1<<k)`.  Plain SAR with
     * no sign bias stays a `>>` (it is a genuine arithmetic shift in source). */
    void sar_or_div(Block& b, const cs_x86& x, uint64_t addr) {
        if (x.op_count < 2) { arith2(b, x, ">>", addr, false); return; }
        const cs_x86_op& d = x.operands[0];
        const cs_x86_op& s = x.operands[1];
        int w = d.size ? d.size : 4;
        ExprP lhs = rvalue(d);
        ExprP rhs = norm_shift_count(rvalue(s));
        /* only handle a constant shift amount */
        if (rhs && rhs->kind == EK::Const && rhs->cval >= 1 && rhs->cval < 64) {
            int k = (int)rhs->cval;
            int signbit = w * 8 - 1;
            ExprP base = sign_bias_base(lhs, w, signbit);
            if (base) {
                int64_t divisor = (int64_t)1 << k;
                ExprP res = mkBinary("/", base, mkConst(divisor, w), w);
                do_dst(b, d, res, addr);
                set_flags_dst(d, res, w);
                return;
            }
        }
        ExprP res = mkBinary(">>", lhs, rhs, w, false);
        do_dst(b, d, res, addr);
        set_flags_dst(d, res, w);
    }

    /* If `e` has the signed-divide sign-bias shape `base + bias` where bias is
     * the isolated sign bit of base (base >>u (W-1)), or
     * `base + ((base SAR (W-1)) >>u (W-k))`, return `base`; else nullptr. */
    ExprP sign_bias_base(const ExprP& e, int w, int signbit) {
        if (!e || e->kind != EK::Binary || e->op != "+") return nullptr;
        ExprP a = e->a, c = e->b;
        /* the bias may be on either side of the + */
        for (int swap = 0; swap < 2; ++swap) {
            ExprP base = swap ? c : a;
            ExprP bias = swap ? a : c;
            if (!base || !bias) continue;
            /* form 1:  bias == base >>u signbit  */
            if (bias->kind == EK::Binary && bias->op == ">>" && bias->is_unsigned &&
                bias->b && bias->b->kind == EK::Const && bias->b->cval == signbit &&
                exprEqual(bias->a, base))
                return clone(base);
            /* form 2:  bias == (base SAR signbit) >>u (W - k)  -- the SAR of the
             * sign extends to all-ones/zeros; we accept any unsigned-shift of a
             * sign-replicating expression of the same base. */
            if (bias->kind == EK::Binary && bias->op == ">>" && bias->is_unsigned &&
                bias->a && bias->a->kind == EK::Binary && bias->a->op == ">>" &&
                bias->a->b && bias->a->b->kind == EK::Const &&
                bias->a->b->cval == signbit && exprEqual(bias->a->a, base))
                return clone(base);
        }
        return nullptr;
    }

    void incdec(Block& b, const cs_x86& x, const std::string& op, uint64_t addr) {
        if (x.op_count < 1) return;
        const cs_x86_op& d = x.operands[0];
        int w = d.size ? d.size : 4;
        ExprP res = mkBinary(op, rvalue(d), mkConst(1, w), w);
        do_dst(b, d, res, addr);
        set_flags_dst(d, res, w);
    }

    /* Win64 passes args 5+ on the stack at [rsp+0x20], [rsp+0x28], ... (just above
     * the 0x20 shadow space). Count the CONTIGUOUS run of such outgoing-arg stores
     * immediately before a call so a 6-arg call (e.g. a `vsnprintf` formatter with a
     * trailing va_list) is not truncated to its 4 register args. Shadow-space homing
     * (disp 8/0x10/0x18, < 0x20) is excluded. Caller-side only — callees are declared
     * unparenthesized, so an occasional over-count just passes a harmless extra arg. */
    /* Reaching-def argument count for an UNKNOWN-arity callee (import / indirect).
     * The Win64 arg registers rcx/rdx/r8/r9 (+xmm0-3) are VOLATILE — clobbered by
     * every call — so an arg register not WRITTEN since the prior call in this block
     * holds a clobbered value, never a real argument (`ShowCursor(0,0xfffffffc,t5)`
     * passed two stale leftovers from a preceding SetWindowLongPtrW). Returns the
     * contiguous count of positions [0..3] actually set up since the last in-block
     * call; -1 if NO prior call is visible (args may be incoming params / set in a
     * predecessor — don't gate). Fills xmm_arg[pos] for a float/double arg in xmmN. */
    int reaching_argc(const Insn& callin, const Block& b, bool xmm_arg[4]) {
        for (int k = 0; k < 4; ++k) xmm_arg[k] = false;
        int pos = -1;
        for (int k = 0; k < (int)b.insn_idx.size(); ++k)
            if (insns[b.insn_idx[k]].addr == callin.addr) { pos = k; break; }
        if (pos < 0) return -1;
        bool int_set[4] = {false,false,false,false};
        bool xmm_set[4] = {false,false,false,false};
        bool prior_call = false;
        for (int k = pos - 1; k >= 0; --k) {
            const Insn& pi = insns[b.insn_idx[k]];
            if (pi.is_call) { prior_call = true; break; }
            const cs_x86& xx = pi.x86;
            for (int o = 0; o < xx.op_count; ++o) {
                if (xx.operands[o].type != X86_OP_REG) continue;
                if (!(xx.operands[o].access & CS_AC_WRITE)) continue;
                Reg r; int w; map_reg(xx.operands[o].reg, r, w);
                if      (r==R_RCX)  int_set[0]=true; else if (r==R_RDX)  int_set[1]=true;
                else if (r==R_R8)   int_set[2]=true; else if (r==R_R9)   int_set[3]=true;
                else if (r==R_XMM0) xmm_set[0]=true; else if (r==R_XMM1) xmm_set[1]=true;
                else if (r==R_XMM2) xmm_set[2]=true; else if (r==R_XMM3) xmm_set[3]=true;
            }
        }
        /* Gate only when the entering volatiles are KNOWN clobbered: a prior in-block
         * call, OR a call that definitely executed on EVERY path before this block
         * (the cross-block state-machine case — args set up in this block, the
         * clobbering call in a predecessor). Otherwise the regs may be incoming
         * params or set in a predecessor -> don't gate. */
        bool clobbered = prior_call ||
            (b.id >= 0 && b.id < (int)call_before_block.size() && call_before_block[b.id]);
        if (!clobbered) return -1;
        int n = 0;
        while (n < 4 && (int_set[n] || xmm_set[n])) {
            if (xmm_set[n] && !int_set[n]) xmm_arg[n] = true;
            ++n;
        }
        return n;
    }

    /* call_before_block[b] = a call instruction definitely executed on EVERY path
     * from the function entry to block b's entry (so the Win64 volatile arg
     * registers are clobbered on entry to b). A forward "must" dataflow: optimistic
     * init (all 1 except entry), iterate down. Used by reaching_argc to gate
     * cross-block stale-arg passing. */
    std::vector<char> call_before_block;
    void compute_call_before_block() {
        int nb = (int)blocks.size();
        call_before_block.assign(nb, 0);
        if (nb == 0) return;
        std::vector<char> has_call(nb, 0);
        for (int i = 0; i < nb; ++i)
            for (int idx : blocks[i].insn_idx)
                if (idx >= 0 && idx < (int)insns.size() && insns[idx].is_call) { has_call[i] = 1; break; }
        int entry = entry_block();
        for (int i = 0; i < nb; ++i) call_before_block[i] = (i == entry) ? 0 : 1;
        bool changed = true; int guard = 0;
        while (changed && guard++ < 100000) {
            changed = false;
            for (int i = 0; i < nb; ++i) {
                if (i == entry) continue;
                char v;
                if (blocks[i].pred.empty()) v = 0;     /* unreachable / no preds */
                else {
                    v = 1;
                    for (int p : blocks[i].pred)
                        if (p >= 0 && p < nb) v = v && (call_before_block[p] || has_call[p]);
                }
                if (v != call_before_block[i]) { call_before_block[i] = v; changed = true; }
            }
        }
    }

    int outgoing_stack_args(const Insn& callin, const Block& b) {
        int pos = -1;
        for (int k = 0; k < (int)b.insn_idx.size(); ++k)
            if (insns[b.insn_idx[k]].addr == callin.addr) { pos = k; break; }
        if (pos < 0) return 0;
        std::set<int> slots;
        for (int k = pos - 1; k >= 0; --k) {
            const Insn& in = insns[b.insn_idx[k]];
            if (in.is_call) break;                 /* a prior call resets the area  */
            const cs_x86& x = in.x86;
            if (x.op_count == 2 && x.operands[0].type == X86_OP_MEM &&
                (in.id == X86_INS_MOV || in.id == X86_INS_MOVSS ||
                 in.id == X86_INS_MOVSD || in.id == X86_INS_MOVAPS)) {
                const x86_op_mem& m = x.operands[0].mem;
                Reg base = R_NONE; int t;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
                if (base == R_RSP && m.index == X86_REG_INVALID &&
                    m.disp >= 0x20 && ((m.disp - 0x20) % 8) == 0 && m.disp <= 0x20 + 8 * 11)
                    slots.insert((int)((m.disp - 0x20) / 8));
            }
        }
        int n = 0; while (slots.count(n)) n++;     /* contiguous from the 5th slot  */
        return n;
    }

    /* An indirect call whose target folds to a constant absolute VA — a function
     * pointer loaded from a read-only global table (`mov rax,[g]; call rax`, g in
     * .rdata) — names the real function instead of `((funcptr)0x180084990)(...)`,
     * so the call-graph / xref edge is recovered. Handles both absolute (base+rva)
     * and bare-rva constants. */
    /* float_mask of the most recently resolved callee (which param positions are
     * XMM float/double args). Read by the call-site arg builder to pull each arg
     * from xmm[i] instead of the integer reg. Reset per lift_call. */
    unsigned char cc_float_mask = 0;
    bool cc_pc_from_sig = false;   /* did the last resolved callee's pc come from sigtab? */

    bool const_callee_name(const ExprP& target, std::string& nm, int& rk, int& pc) {
        ExprP f = fold(clone(target));
        if (!f || f->kind != EK::Const) return false;
        uint64_t addr = (uint64_t)f->cval;
        uint64_t rva = (addr >= e->base && e->base) ? (addr - e->base) : addr;
        /* a call target is, by construction, a code address. Accept any in-image
         * RVA (preferring a known function for its sigtab arity). Resolving even
         * an engine-unidentified target restores the call-graph edge. */
        if (rva == 0 || rva >= e->image_size) return false;
        nm = name_for_rva(rva);
        if (nm.empty()) return false;
        rk = 2; pc = 4; cc_pc_from_sig = false;
        if (sigtab && sigtab->count(rva)) {
            rk = sigtab->at(rva).ret_kind; pc = sigtab->at(rva).param_count;
            cc_float_mask = sigtab->at(rva).float_mask;
            cc_pc_from_sig = true;
        }
        return true;
    }

    /* Known arities/return-kinds for common imported Win32 / CRT / COM APIs. The
     * Win64 arg registers are volatile, so a callee's true arity cannot be
     * recovered from the call site when the caller's own params sit in unused arg
     * registers — `GetSystemMetrics(0x22, a2, t711, a4)` shows 3 phantom leftovers.
     * A signature table (as IDA/Ghidra ship) fixes it for EVERY binary. Matches the
     * bare or A/W-suffixed name. Returns false when unknown (fall back to reaching-
     * def gating). rk: 0 void, 1 int, 2 long long/pointer. */
    static bool known_api(const std::string& nm, int& argc, int& rk) {
        struct E { const char* n; int a; int r; };
        static const E tbl[] = {
            /* kernel32 */
            {"GetLastError",0,1},{"SetLastError",1,0},{"GetCurrentThreadId",0,1},
            {"GetCurrentProcessId",0,1},{"GetCurrentProcess",0,2},{"GetCurrentThread",0,2},
            {"GetTickCount",0,1},{"GetTickCount64",0,2},{"QueryPerformanceCounter",1,1},
            {"QueryPerformanceFrequency",1,1},{"Sleep",1,0},{"CloseHandle",1,1},
            {"GetProcAddress",2,2},{"GetModuleHandle",1,2},{"LoadLibrary",1,2},
            {"FreeLibrary",1,1},{"GetStdHandle",1,2},{"ExitProcess",1,0},
            {"HeapAlloc",3,2},{"HeapFree",3,1},{"HeapReAlloc",4,2},{"GetProcessHeap",0,2},
            {"VirtualAlloc",4,2},{"VirtualFree",3,1},{"VirtualProtect",4,1},
            {"EnterCriticalSection",1,0},{"LeaveCriticalSection",1,0},
            {"InitializeCriticalSection",1,0},{"DeleteCriticalSection",1,0},
            /* msvcp140 <mutex> lowering: std::mutex::lock/unlock bottom out here.
             * Imported, so they were already NAMED — but absent from this table
             * their arity fell back to the pc=4 default and printed 3 junk args.
             * _Mtx_destroy is the only void one; the rest return an errno_t. */
            {"_Mtx_lock",1,1},{"_Mtx_unlock",1,1},{"_Mtx_trylock",1,1},
            {"_Mtx_init",2,1},{"_Mtx_destroy",1,0},
            {"WriteFile",5,1},{"ReadFile",5,1},{"GetFileSize",2,1},
            {"MultiByteToWideChar",6,1},{"WideCharToMultiByte",8,1},
            {"FormatMessage",7,1},{"OutputDebugString",1,0},{"IsDebuggerPresent",0,1},
            /* user32 */
            {"GetSystemMetrics",1,1},{"MessageBox",4,1},{"ShowWindow",2,1},
            {"ShowCursor",1,1},{"GetDC",1,2},{"ReleaseDC",2,1},{"DestroyWindow",1,1},
            {"DefWindowProc",4,2},{"SendMessage",4,2},{"PostMessage",4,1},
            {"GetWindowLongPtr",2,2},{"SetWindowLongPtr",3,2},{"GetClientRect",2,1},
            {"GetWindowRect",2,1},{"SetWindowPos",7,1},{"UpdateWindow",1,1},
            {"InvalidateRect",3,1},{"GetCursorPos",1,1},{"SetCursorPos",2,1},
            /* ole32 / combase */
            {"CoInitialize",1,1},{"CoInitializeEx",2,1},{"CoUninitialize",0,0},
            {"CoCreateInstance",5,1},{"CoTaskMemAlloc",1,2},{"CoTaskMemFree",1,0},
            {"RevokeDragDrop",1,1},{"RegisterDragDrop",2,1},{"OleInitialize",1,1},
            /* CRT */
            {"malloc",1,2},{"free",1,0},{"realloc",2,2},{"calloc",2,2},
            {"memcpy",3,2},{"memmove",3,2},{"memset",3,2},{"memcmp",3,1},
            {"strlen",1,2},{"strcmp",2,1},{"strncmp",3,1},{"strcpy",2,2},
            {"strncpy",3,2},{"strcat",2,2},{"strchr",2,2},{"strstr",2,2},
            {"wcslen",1,2},{"abort",0,0},{"exit",1,0},{"_errno",0,2},
            {"wcscmp",2,1},{"wcscpy",2,2},{"wcscat",2,2},{"wcschr",2,2},{"wcsncmp",3,1},
            {"_XcptFilter",2,1},{"_amsg_exit",1,0},{"_initterm",2,0},{"__C_specific_handler",4,1},
            /* TLS (kernel32) — these were defaulting to 4-args-then-trim, giving the
             * wrong count (TlsFree(x,a2), TlsAlloc(a1,..), TlsGetValue()). */
            {"TlsAlloc",0,1},{"TlsFree",1,1},{"TlsGetValue",1,2},{"TlsSetValue",2,1},
            /* time (kernel32) */
            {"GetSystemTimeAsFileTime",1,0},{"GetSystemTime",1,0},{"GetLocalTime",1,0},
            {"SystemTimeToFileTime",2,1},{"FileTimeToSystemTime",2,1},
            {"FileTimeToLocalFileTime",2,1},{"GetFileTime",4,1},{"SetFileTime",4,1},
            /* file / module (kernel32) */
            {"CreateFile",7,2},{"DeleteFile",1,1},{"GetFileAttributes",1,1},
            {"GetFileAttributesEx",3,1},{"SetFilePointer",4,1},{"SetFilePointerEx",4,1},
            {"GetFileSizeEx",2,1},{"FlushFileBuffers",1,1},{"SetEndOfFile",1,1},
            {"GetModuleFileName",3,1},{"GetModuleHandleEx",3,1},{"LoadLibraryEx",3,2},
            {"GetFullPathName",4,1},{"GetTempPath",2,1},{"GetTempFileName",4,1},
            {"FindFirstFile",2,2},{"FindNextFile",2,1},{"FindClose",1,1},
            {"GetEnvironmentVariable",3,1},{"ExpandEnvironmentStrings",3,1},
            /* memory (kernel32) */
            {"LocalAlloc",2,2},{"LocalFree",1,2},{"LocalLock",1,2},{"LocalUnlock",1,1},
            {"GlobalAlloc",2,2},{"GlobalFree",1,2},{"GlobalLock",1,2},{"GlobalUnlock",1,1},
            {"RtlCaptureContext",1,0},{"RaiseException",4,0},
            /* sync (kernel32) */
            {"WaitForSingleObject",2,1},{"WaitForMultipleObjects",4,1},
            {"WaitForSingleObjectEx",3,1},{"WaitForMultipleObjectsEx",5,1},
            {"CreateThread",6,2},{"CreateEvent",4,2},{"SetEvent",1,1},{"ResetEvent",1,1},
            {"CreateMutex",3,2},{"ReleaseMutex",1,1},
            {"CreateSemaphore",4,2},{"OpenSemaphore",3,2},{"ReleaseSemaphore",3,1},
            {"CreateSemaphoreEx",6,2},
            /* path helpers (kernel32) — were defaulting to 4 args, leaving a stale
             * leftover register as a phantom 4th arg (GetShortPathNameW(p,b,n,-1)). */
            {"GetShortPathName",3,1},{"GetLongPathName",3,1},
            {"GetFinalPathNameByHandle",4,1},{"PathFileExists",1,1},
            /* SRW locks / one-time init / threadpool (kernel32) — 1-arg lock ops
             * were showing 2 (AcquireSRWLockShared(a2,a2)); pool ops showed 0. */
            {"InitializeSRWLock",1,0},{"AcquireSRWLockShared",1,0},
            {"ReleaseSRWLockShared",1,0},{"AcquireSRWLockExclusive",1,0},
            {"ReleaseSRWLockExclusive",1,0},{"TryAcquireSRWLockExclusive",1,1},
            {"TryAcquireSRWLockShared",1,1},
            {"InitOnceExecuteOnce",4,1},{"InitOnceBeginInitialize",4,1},
            {"InitOnceComplete",3,1},{"InitOnceInitialize",1,0},
            {"CreateThreadpoolTimer",3,2},{"SetThreadpoolTimer",4,0},
            {"CloseThreadpoolTimer",1,0},{"WaitForThreadpoolTimerCallbacks",2,0},
            {"CreateThreadpoolWork",3,2},{"SubmitThreadpoolWork",1,0},
            {"CloseThreadpoolWork",1,0},{"WaitForThreadpoolWorkCallbacks",2,0},
            {"CreateThreadpoolWait",3,2},{"SetThreadpoolWait",3,0},
            {"CreateFileMapping",6,2},{"MapViewOfFile",5,2},{"UnmapViewOfFile",1,1},
            {"DuplicateHandle",7,1},{"GetOverlappedResult",4,1},
            {"InitializeCriticalSectionAndSpinCount",2,1},{"TryEnterCriticalSection",1,1},
            {"InterlockedIncrement",1,1},{"InterlockedDecrement",1,1},
            {"InterlockedExchange",2,1},{"InterlockedCompareExchange",3,1},
            /* strings (kernel32) */
            {"lstrlen",1,1},{"lstrcmp",2,1},{"lstrcmpi",2,1},{"lstrcpy",2,2},
            {"lstrcpyn",3,2},{"lstrcat",2,2},
            /* registry (advapi32) */
            {"RegOpenKeyEx",5,1},{"RegCreateKeyEx",9,1},{"RegQueryValueEx",6,1},
            {"RegSetValueEx",6,1},{"RegCloseKey",1,1},{"RegDeleteValue",2,1},
            {"RegEnumKeyEx",8,1},{"RegEnumValue",8,1},{"RegQueryInfoKey",12,1},
            /* NT syscalls (ntdll) — NTSTATUS return (rk 1). These are called via the
             * import thunk, so pc defaulted to 4 and the 5th+ STACK args were dropped
             * (NtDeviceIoControlFile has 10, NtClose only 1). Definitive arities: */
            {"NtClose",1,1},{"ZwClose",1,1},
            {"NtDeviceIoControlFile",10,1},{"ZwDeviceIoControlFile",10,1},
            {"NtFsControlFile",10,1},
            {"NtOpenFile",6,1},{"ZwOpenFile",6,1},
            {"NtCreateFile",11,1},{"ZwCreateFile",11,1},
            {"NtReadFile",9,1},{"NtWriteFile",9,1},
            {"NtQueryInformationFile",5,1},{"NtSetInformationFile",5,1},
            {"NtQueryVolumeInformationFile",5,1},
            {"NtWaitForSingleObject",3,1},{"NtSetEvent",2,1},{"NtClearEvent",1,1},
            {"NtAllocateVirtualMemory",6,1},{"NtFreeVirtualMemory",4,1},
            {"NtProtectVirtualMemory",5,1},{"NtQueryVirtualMemory",6,1},
            {"NtOpenKey",3,1},{"NtCreateKey",7,1},{"NtQueryValueKey",6,1},
            {"NtSetValueKey",6,1},{"NtDeleteValueKey",2,1},{"NtEnumerateValueKey",6,1},
            {"NtQueryInformationProcess",5,1},{"NtQueryInformationThread",5,1},
            {"NtQuerySystemInformation",4,1},{"NtQueryInformationToken",5,1},
            {"NtOpenProcessToken",3,1},{"NtOpenThreadToken",4,1},
            /* Rtl heap / helpers (ntdll) — pointer return (rk 2) for allocators */
            {"RtlAllocateHeap",3,2},{"RtlFreeHeap",3,1},{"RtlReAllocateHeap",4,2},
            {"RtlSizeHeap",3,2},{"RtlCreateHeap",6,2},{"RtlDestroyHeap",1,2},
            {"RtlInitUnicodeString",2,0},{"RtlInitAnsiString",2,0},
            {"RtlFreeUnicodeString",1,0},{"RtlCompareUnicodeString",3,1},
            {"RtlEqualUnicodeString",3,1},{"RtlCopyUnicodeString",2,0},
            {"RtlNtStatusToDosError",1,1},{"RtlGetLastWin32Error",0,1},
            {"RtlSetLastWin32Error",1,0},{"RtlEnterCriticalSection",1,1},
            {"RtlLeaveCriticalSection",1,1},{"RtlDeleteCriticalSection",1,1},
            {"RtlInitializeCriticalSection",1,1},
            /* delay-load runtime helper (returns FARPROC pointer, rk 2). Called via
             * the delay-import IAT with 5+ args set up on the stack. */
            {"ResolveDelayLoadedAPI",6,2},{"__delayLoadHelper2",2,2},
            {"DelayLoadFailureHook",2,2},
        };
        /* strip a trailing 'A'/'W' ANSI/wide suffix for the lookup */
        std::string base = nm;
        if (base.size() > 1 && (base.back() == 'A' || base.back() == 'W')) {
            char p = base[base.size() - 2];
            if (p >= 'a' && p <= 'z') base.pop_back();   /* only if it reads like a word */
        }
        for (const E& e : tbl)
            if (nm == e.n || base == e.n) { argc = e.a; rk = e.r; return true; }
        return false;
    }

    /* Backing type for every name api_param_types() can produce. INTEGER-backed on
     * purpose: a pointer and a 64-bit integer occupy the identical x64 register
     * slot, so the callee reads rcx/edx unchanged and NO call site needs a cast it
     * did not already need. A pointer-backed spelling (`typedef void* HANDLE`)
     * would instead demand `(HANDLE)(uintptr_t)x` at every arg — measured as a
     * large char regression for the same information, so it is not worth it here.
     * Spelled in BASE C types deliberately: apply_stdint_types() rewrites this text
     * when enabled, and under DS_NO_STDINT neither it nor <stdint.h> is emitted, so
     * a `uint64_t` spelling would be a hard C2065 in that mode. */
    static const char* api_type_backing(const std::string& t) {
        if (t == "BOOL") return "int";
        if (t == "DWORD" || t == "UINT") return "unsigned int";
        return "unsigned long long";
    }

    /* TEB (Thread Environment Block) field at a gs-relative offset. `__readgsqword(0x58)` is
     * raw and decidable: the x64 TEB layout is FIXED, so every constant offset names a specific
     * thread-context field. Recovering it turns thread-local machinery from pointer arithmetic
     * into what it is. Returns "" for an offset we do not have a name for (kept as the number).
     * Every name is recorded so its #define prelude is emitted (the units compile /TC with no
     * winnt.h). */
    static const char* teb_field_name(int64_t off) {
        switch (off) {
            case 0x00: return "TEB_ExceptionList";        /* NT_TIB.ExceptionList */
            case 0x08: return "TEB_StackBase";
            case 0x10: return "TEB_StackLimit";
            case 0x30: return "TEB_Self";                 /* NtCurrentTeb() */
            case 0x40: return "TEB_ProcessEnvironmentBlock";
            case 0x48: return "TEB_ProcessId";            /* ClientId.UniqueProcess */
            case 0x50: return "TEB_ThreadId";             /* ClientId.UniqueThread */
            case 0x58: return "TEB_ThreadLocalStoragePointer";
            case 0x60: return "TEB_PEB";
            case 0x68: return "TEB_LastErrorValue";
            case 0x1480: return "TEB_TlsSlots";           /* TlsSlots[0] */
            case 0x2C: return "TEB_TlsExpansionSlots";
            default: return nullptr;
        }
    }

    /* SYMBOLIC CONSTANTS for Win32 API parameters.
     *
     * `VirtualAlloc(v10, 0x1000, 0x3000, 0x40)` is the single most important line in a lot of
     * binaries and it says nothing. It means
     *     VirtualAlloc(v10, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
     * i.e. "allocate committed RWX memory" -- the shellcode tell. The magic numbers are not
     * ambiguous: the API's own contract fixes what each parameter's bits mean, so this is the
     * type library again, spent on values instead of types.
     *
     * FLAGS  = OR-able bits; every bit must be covered by a name or the whole thing is
     *          declined (a leftover bit would make the rendering a LIE about the value).
     * ENUM   = one exact value; no partial match.
     * Keyed by (base API name, parameter index). The A/W suffix is stripped by the caller.
     * Only parameters whose constants are unambiguous are listed -- a size, a count or a
     * pointer is absent on purpose. */
    enum ConstKind { CK_NONE = 0, CK_FLAGS, CK_ENUM };
    struct ApiConst { const char* api; int pidx; int kind; const char* names[10]; long long vals[10]; };
    static const ApiConst* api_const_table(const std::string& base, int pidx) {
        static const ApiConst T[] = {
            /* VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) */
            {"VirtualAlloc", 2, CK_FLAGS,
             {"MEM_COMMIT","MEM_RESERVE","MEM_DECOMMIT","MEM_RELEASE","MEM_RESET","MEM_TOP_DOWN",0},
             {0x1000,0x2000,0x4000,0x8000,0x80000,0x100000,0}},
            {"VirtualAlloc", 3, CK_FLAGS,
             {"PAGE_NOACCESS","PAGE_READONLY","PAGE_READWRITE","PAGE_WRITECOPY","PAGE_EXECUTE",
              "PAGE_EXECUTE_READ","PAGE_EXECUTE_READWRITE","PAGE_EXECUTE_WRITECOPY","PAGE_GUARD",0},
             {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x100,0}},
            /* VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) */
            {"VirtualProtect", 2, CK_FLAGS,
             {"PAGE_NOACCESS","PAGE_READONLY","PAGE_READWRITE","PAGE_WRITECOPY","PAGE_EXECUTE",
              "PAGE_EXECUTE_READ","PAGE_EXECUTE_READWRITE","PAGE_EXECUTE_WRITECOPY","PAGE_GUARD",0},
             {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x100,0}},
            /* VirtualFree(lpAddress, dwSize, dwFreeType) */
            {"VirtualFree", 2, CK_FLAGS, {"MEM_DECOMMIT","MEM_RELEASE",0}, {0x4000,0x8000,0}},
            /* GetStdHandle(nStdHandle) */
            {"GetStdHandle", 0, CK_ENUM,
             {"STD_INPUT_HANDLE","STD_OUTPUT_HANDLE","STD_ERROR_HANDLE",0}, {-10,-11,-12,0}},
            /* WaitForSingleObject(hHandle, dwMilliseconds) */
            {"WaitForSingleObject", 1, CK_ENUM, {"INFINITE",0}, {0xFFFFFFFFLL,0}},
            /* CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreationDisposition, ..) */
            {"CreateFile", 1, CK_FLAGS, {"GENERIC_READ","GENERIC_WRITE","GENERIC_EXECUTE","GENERIC_ALL",0},
             {0x80000000LL,0x40000000LL,0x20000000LL,0x10000000LL,0}},
            {"CreateFile", 2, CK_FLAGS, {"FILE_SHARE_READ","FILE_SHARE_WRITE","FILE_SHARE_DELETE",0},
             {0x1,0x2,0x4,0}},
            {"CreateFile", 4, CK_ENUM,
             {"CREATE_NEW","CREATE_ALWAYS","OPEN_EXISTING","OPEN_ALWAYS","TRUNCATE_EXISTING",0},
             {1,2,3,4,5,0}},
            /* HeapAlloc(hHeap, dwFlags, dwBytes) */
            {"HeapAlloc", 1, CK_FLAGS, {"HEAP_NO_SERIALIZE","HEAP_GENERATE_EXCEPTIONS","HEAP_ZERO_MEMORY",0},
             {0x1,0x4,0x8,0}},
            /* OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) */
            {"OpenProcess", 0, CK_FLAGS,
             {"PROCESS_TERMINATE","PROCESS_CREATE_THREAD","PROCESS_VM_OPERATION","PROCESS_VM_READ",
              "PROCESS_VM_WRITE","PROCESS_QUERY_INFORMATION","SYNCHRONIZE",0},
             {0x1,0x2,0x8,0x10,0x20,0x400,0x100000,0}},
            {0,0,0,{0},{0}},
        };
        for (const ApiConst* p = T; p->api; ++p)
            if (pidx == p->pidx && base == p->api) return p;
        return nullptr;
    }
    /* Render `v` for (api, pidx) as symbolic names, or "" when it cannot be done EXACTLY.
     * Every name used is reported via `used` so the caller can emit its #define -- the dumped
     * units compile /TC standalone with no windows.h, so an undefined MEM_COMMIT is a C2065. */
    static std::string api_const_str(const std::string& nm, int pidx, long long v,
                                     std::map<std::string,long long>& used) {
        static const bool off = std::getenv("DS_NO_APICONST") != nullptr;
        if (off) return "";
        std::string base = nm;
        if (base.size() > 1 && (base.back() == 'A' || base.back() == 'W')) {
            char pc = base[base.size() - 2];
            if (pc >= 'a' && pc <= 'z') base.pop_back();
        }
        const ApiConst* t = api_const_table(base, pidx);
        if (!t) return "";
        if (t->kind == CK_ENUM) {
            for (int i = 0; t->names[i]; ++i)
                if (t->vals[i] == v) { used[t->names[i]] = t->vals[i]; return t->names[i]; }
            return "";                                  /* not a value we know: say nothing */
        }
        /* FLAGS: every set bit must be named, else the render would drop information. */
        if (v == 0) return "";                          /* 0 is just 0 -- naming it adds nothing */
        long long left = v; std::string out;
        std::map<std::string,long long> mine;
        for (int i = 0; t->names[i]; ++i) {
            long long b = t->vals[i];
            if (b && (left & b) == b) {
                if (!out.empty()) out += "|";
                out += t->names[i]; mine[t->names[i]] = b; left &= ~b;
            }
        }
        if (left != 0 || out.empty()) return "";        /* an unnamed bit remains -> decline */
        for (auto& kv : mine) used[kv.first] = kv.second;
        return out;
    }

    /* Win32 RETURN types — the other half of the type library, and the one that actually
     * types the reader's VARIABLES rather than just a prototype:
     *     v7 = CreateFileW(...)      ->  HANDLE v7 = CreateFileW(...)
     *     v3 = GetModuleHandleW(0)   ->  HMODULE v3 = GetModuleHandleW(0)
     * A parameter type only says what a call EXPECTS; a return type says what a local IS,
     * and that is what propagates outward through the rest of the function.
     *
     * Only APIs whose return is a real named type are listed. An API returning a plain int
     * or a count is deliberately ABSENT — "" means "say nothing", never a guess. Every name
     * here must exist in api_type_backing (integer-backed), so a typed local still compiles
     * and no call site needs a new cast.
     * The A/W suffix is stripped by the caller before lookup, exactly like api_param_types. */
    static std::string api_ret_type(const std::string& nm) {
        static const bool off = std::getenv("DS_NO_APITYPES") != nullptr;
        if (off) return "";
        struct R { const char* api; const char* ty; };
        static const R tbl[] = {
            /* module / library handles */
            {"GetModuleHandle", "HMODULE"}, {"LoadLibrary", "HMODULE"},
            {"LoadLibraryEx", "HMODULE"},
            {"GetProcAddress", "FARPROC"},
            /* kernel object handles */
            {"CreateFile", "HANDLE"},       {"CreateThread", "HANDLE"},
            {"CreateMutex", "HANDLE"},      {"CreateEvent", "HANDLE"},
            {"CreateSemaphore", "HANDLE"},  {"OpenProcess", "HANDLE"},
            {"OpenThread", "HANDLE"},       {"GetCurrentProcess", "HANDLE"},
            {"GetCurrentThread", "HANDLE"}, {"GetStdHandle", "HANDLE"},
            {"CreateToolhelp32Snapshot", "HANDLE"}, {"FindFirstFile", "HANDLE"},
            {"GetProcessHeap", "HANDLE"},
            /* memory */
            {"HeapAlloc", "LPVOID"},        {"HeapReAlloc", "LPVOID"},
            {"VirtualAlloc", "LPVOID"},     {"VirtualAllocEx", "LPVOID"},
            {"MapViewOfFile", "LPVOID"},    {"LocalAlloc", "LPVOID"},
            {"GlobalAlloc", "LPVOID"},
            /* windows */
            {"CreateWindowEx", "HWND"},     {"FindWindow", "HWND"},
            {"GetForegroundWindow", "HWND"},{"GetActiveWindow", "HWND"},
            {"GetDesktopWindow", "HWND"},   {"WindowFromPoint", "HWND"},
            {"GetDC", "HDC"},               {"BeginPaint", "HDC"},
            /* dword-returning status/id APIs */
            {"GetLastError", "DWORD"},      {"GetCurrentProcessId", "DWORD"},
            {"GetCurrentThreadId", "DWORD"},{"GetTickCount", "DWORD"},
            {"WaitForSingleObject", "DWORD"}, {"GetFileAttributes", "DWORD"},
            {"GetFileSize", "DWORD"},       {"ResumeThread", "DWORD"},
            {"SuspendThread", "DWORD"},     {"GetModuleFileName", "DWORD"},
        };
        std::string base = nm;
        if (base.size() > 1) {                  /* strip the A/W suffix, as known_api does */
            char c = base.back();
            if (c == 'A' || c == 'W') {
                std::string t = base.substr(0, base.size() - 1);
                for (const R& r : tbl) if (t == r.api) return r.ty;
            }
        }
        for (const R& r : tbl) if (base == r.api) return r.ty;
        return "";
    }

    /* Win32 PARAMETER TYPES for imports known_api() already pins an exact arity on,
     * so `long long VirtualProtect(long long, long long, long long, long long)`
     * reads `BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, LPDWORD)` instead.
     *
     * The arity here is NEVER independently trusted. known_api()'s argc is the sole
     * authority (callee_typed_proto_arity gates the proto emitter AND the call-site
     * clamp on it), so a list whose length disagrees with it is REJECTED below and
     * the caller falls back to `long long`. That makes a typo in this table
     * structurally incapable of desyncing a proto from its call site — the C2197/
     * C2198 class this feature could otherwise reintroduce.
     *
     * `LPCTSTR`/`LPTSTR` are placeholders, not emitted names: known_api() strips the
     * A/W suffix and looks the BASE name up, so one row necessarily serves both
     * CreateFileA and CreateFileW. Expanding by the caller's real suffix is what
     * keeps `GetModuleHandleW(LPCWSTR)` from being mistyped as LPCSTR. */
    static bool api_param_types(const std::string& nm, std::vector<std::string>& out) {
        static const bool off = std::getenv("DS_NO_APITYPES") != nullptr;
        if (off) return false;
        struct T { const char* n; const char* p; };
        static const T tbl[] = {
            /* kernel32 — module / process */
            {"SetLastError",      "DWORD"},
            {"Sleep",             "DWORD"},
            {"ExitProcess",       "UINT"},
            {"CloseHandle",       "HANDLE"},
            {"GetModuleHandle",   "LPCTSTR"},
            {"LoadLibrary",       "LPCTSTR"},
            {"LoadLibraryEx",     "LPCTSTR, HANDLE, DWORD"},
            {"FreeLibrary",       "HMODULE"},
            {"GetProcAddress",    "HMODULE, LPCSTR"},
            {"GetModuleFileName", "HMODULE, LPTSTR, DWORD"},
            {"GetStdHandle",      "DWORD"},
            {"OutputDebugString", "LPCTSTR"},
            /* kernel32 — heap / virtual memory */
            {"HeapAlloc",         "HANDLE, DWORD, SIZE_T"},
            {"HeapFree",          "HANDLE, DWORD, LPVOID"},
            {"HeapReAlloc",       "HANDLE, DWORD, LPVOID, SIZE_T"},
            {"VirtualAlloc",      "LPVOID, SIZE_T, DWORD, DWORD"},
            {"VirtualFree",       "LPVOID, SIZE_T, DWORD"},
            {"VirtualProtect",    "LPVOID, SIZE_T, DWORD, LPDWORD"},
            /* kernel32 — critical sections */
            {"InitializeCriticalSection", "LPCRITICAL_SECTION"},
            {"EnterCriticalSection",      "LPCRITICAL_SECTION"},
            {"LeaveCriticalSection",      "LPCRITICAL_SECTION"},
            {"DeleteCriticalSection",     "LPCRITICAL_SECTION"},
            /* kernel32 — file I/O */
            {"CreateFile",        "LPCTSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE"},
            {"WriteFile",         "HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID"},
            {"ReadFile",          "HANDLE, LPVOID, DWORD, LPDWORD, LPVOID"},
            {"GetFileSize",       "HANDLE, LPDWORD"},
            {"GetFileSizeEx",     "HANDLE, LPVOID"},
            {"FlushFileBuffers",  "HANDLE"},
            {"SetEndOfFile",      "HANDLE"},
            {"DeleteFile",        "LPCTSTR"},
            {"GetFileAttributes", "LPCTSTR"},
            {"FindFirstFile",     "LPCTSTR, LPVOID"},
            {"FindNextFile",      "HANDLE, LPVOID"},
            {"FindClose",         "HANDLE"},
            {"GetEnvironmentVariable", "LPCTSTR, LPTSTR, DWORD"},
            /* kernel32 — sync / TLS / time */
            {"WaitForSingleObject", "HANDLE, DWORD"},
            {"SetEvent",          "HANDLE"},
            {"ResetEvent",        "HANDLE"},
            {"ReleaseMutex",      "HANDLE"},
            {"CreateThread",      "LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD"},
            {"TlsFree",           "DWORD"},
            {"TlsGetValue",       "DWORD"},
            {"TlsSetValue",       "DWORD, LPVOID"},
            {"QueryPerformanceCounter",   "LPVOID"},
            {"QueryPerformanceFrequency", "LPVOID"},
            {"GetSystemTimeAsFileTime",   "LPVOID"},
            /* kernel32 — code pages. Explicitly LPCSTR/LPCWSTR (not the T
             * placeholder): these take BOTH widths regardless of any suffix. */
            {"MultiByteToWideChar", "UINT, DWORD, LPCSTR, int, LPWSTR, int"},
            {"WideCharToMultiByte", "UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL"},
            /* user32 */
            {"GetSystemMetrics",  "int"},
            {"ShowWindow",        "HWND, int"},
            {"DestroyWindow",     "HWND"},
            {"GetDC",             "HWND"},
            {"ReleaseDC",         "HWND, HDC"},
            {"GetClientRect",     "HWND, LPVOID"},
            {"GetWindowRect",     "HWND, LPVOID"},
            {"MessageBox",        "HWND, LPCTSTR, LPCTSTR, UINT"},
        };
        /* mirror known_api's A/W normalization so CreateFileW hits the base row */
        std::string base = nm;
        bool wide = false, tagged = false;
        if (base.size() > 1 && (base.back() == 'A' || base.back() == 'W')) {
            char p = base[base.size() - 2];
            if (p >= 'a' && p <= 'z') { wide = (base.back() == 'W'); tagged = true; base.pop_back(); }
        }
        (void)tagged;
        const char* plist = nullptr;
        for (const T& e : tbl)
            if (nm == e.n || base == e.n) { plist = e.p; break; }
        if (!plist) return false;

        out.clear();
        std::string cur;
        for (const char* q = plist; ; ++q) {
            if (*q == ',' || *q == '\0') {
                if (!cur.empty()) {
                    if (cur == "LPCTSTR") cur = wide ? "LPCWSTR" : "LPCSTR";
                    else if (cur == "LPTSTR") cur = wide ? "LPWSTR" : "LPSTR";
                    out.push_back(cur);
                    cur.clear();
                }
                if (*q == '\0') break;
                continue;
            }
            if (*q != ' ') cur += *q;
        }
        /* THE SAFETY VALVE: known_api's argc is the authority both the proto and the
         * call-site clamp already agree on. A row that disagrees loses its types
         * rather than shifting an arg boundary. */
        int argc = 0, rk = 0;
        if (!known_api(nm, argc, rk) || (int)out.size() != argc) { out.clear(); return false; }
        return true;
    }

    /* LOCK RECOVERY: classify a callee name as a lock ACQUIRE (1) or RELEASE (2).
     * Only the primitives whose pairing is unambiguous are listed — Initialize/
     * Delete/InitOnce* touch a lock without guarding a region, and naming them
     * "acquire" would annotate a scope that does not exist. A `j_` import thunk
     * is stripped the same way the tail-call arity override does. */
    static int lock_api_kind(const std::string& nm) {
        std::string b = (nm.rfind("j_", 0) == 0) ? nm.substr(2) : nm;
        static const char* acq[] = {
            "EnterCriticalSection", "TryEnterCriticalSection",
            "RtlEnterCriticalSection", "AcquireSRWLockShared",
            "AcquireSRWLockExclusive", "TryAcquireSRWLockShared",
            "TryAcquireSRWLockExclusive", "_Mtx_lock", "_Mtx_trylock",
        };
        static const char* rel[] = {
            "LeaveCriticalSection", "RtlLeaveCriticalSection",
            "ReleaseSRWLockShared", "ReleaseSRWLockExclusive", "_Mtx_unlock",
        };
        for (const char* s : acq) if (b == s) return 1;
        for (const char* s : rel) if (b == s) return 2;
        return 0;
    }

