/* Decisive test for the VEX->SSE remap width hazard.
 *
 * The remap in 13_lift_insn.inc rewrites VMOVDQU -> MOVDQU with NO operand-size guard.
 * The SSE handler commits a packed store only when `OP(0).size == 16`; a ymm memory
 * operand is 32, so it skips that block and falls through to the bare `do_dst` at the
 * bottom of the case. The question this fixture answers: does that emit a WRONG NARROW
 * STORE (a silent lie -- 32 bytes written, ~8 reported) or drop it loudly?
 *
 * ymm_copy32 is the minimal case: one 32-byte load, one 32-byte store, nothing else.
 * Whatever the decompiler says about it is unambiguous.
 * Build: cl /O2 /LD /TC /arch:AVX2
 */
#include <immintrin.h>

/* ONE 32-byte load + ONE 32-byte store. Truth: dst[0..31] = src[0..31]. */
__declspec(dllexport) void ymm_copy32(char* dst, const char* src) {
    __m256i v = _mm256_loadu_si256((const __m256i*)src);
    _mm256_storeu_si256((__m256i*)dst, v);
}

/* Non-temporal 32-byte store (vmovntdq -- 30 sites in NullWare). */
__declspec(dllexport) void ymm_nt32(char* dst, const char* src) {
    __m256i v = _mm256_loadu_si256((const __m256i*)src);
    _mm256_stream_si256((__m256i*)dst, v);
}

/* 32-byte xor then store: the value is COMPUTED, so a narrow store cannot be excused
 * as "copied the low half" -- it would be reporting the wrong computation entirely. */
__declspec(dllexport) void ymm_xor32(char* dst, const char* a, const char* b) {
    __m256i x = _mm256_loadu_si256((const __m256i*)a);
    __m256i y = _mm256_loadu_si256((const __m256i*)b);
    _mm256_storeu_si256((__m256i*)dst, _mm256_xor_si256(x, y));
}

/* CONTROL: the 128-bit form the remap was actually built for. This one MUST stay
 * correct -- if a width guard breaks this, the guard is too broad. */
__declspec(dllexport) void xmm_copy16(char* dst, const char* src) {
    __m128i v = _mm_loadu_si128((const __m128i*)src);
    _mm_storeu_si128((__m128i*)dst, v);
}

/* CONTROL: VEX-encoded but 128-bit (vmovdqu xmm). /arch:AVX2 emits the v-prefixed
 * form even for 128-bit ops, so this is the common case in an AVX binary and MUST
 * keep working through the remap. */
__declspec(dllexport) float vex_scalar(float a, float b) {
    return a * b + a / b;
}
