/* mathextra: /O2 behavioral test for the inlined-sqrt value-lift (SQRTSS/SQRTSD)
 * and the 64-bit double sign/bit tests (ibits width). Uses _mm_sqrt_ss/_sd so the
 * compiler emits a BARE sqrtss/sqrtsd (no CRT slow-path helper to link) — the same
 * opcode the decompiler used to drop (leaving the dep-breaking xorps zero, so the
 * function returned 0.0). The union bit tests exercise the double (8-byte)
 * reinterpret masked with a 64-bit constant. */
#include <stdint.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#define API __declspec(dllexport)

static float  ssqrt(float x)  { return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(x))); }   /* bare sqrtss */
static double dsqrt(double x) { return _mm_cvtsd_f64(_mm_sqrt_sd(_mm_setzero_pd(), _mm_set_sd(x))); } /* bare sqrtsd */

/* ---- inlined sqrt fast path ---- */
API float  vec_len2(float x, float y)              { return ssqrt(x*x + y*y); }
API float  vec_len3(float x, float y, float z)     { return ssqrt(x*x + y*y + z*z); }
API float  fdist(float ax, float ay, float bx, float by) { float dx=ax-bx, dy=ay-by; return ssqrt(dx*dx + dy*dy); }
API double dhypot(double a, double b)              { return dsqrt(a*a + b*b); }
API float  fnorm_x(float x, float y)               { float L = ssqrt(x*x + y*y); return L > 0.0f ? x / L : 0.0f; }

/* ---- 64-bit double bit/sign tests (ibits must read all 8 bytes) ---- */
API int    d_signbit(double x)   { union { double d; uint64_t u; } v; v.d = x; return (int)(v.u >> 63); }
API int    d_isneg(double x)     { union { double d; uint64_t u; } v; v.d = x; return (v.u & 0x8000000000000000ULL) != 0; }
API double d_fabs(double x)      { union { double d; uint64_t u; } v; v.d = x; v.u &= 0x7fffffffffffffffULL; return v.d; }
API double d_copysign(double m, double s) { union { double d; uint64_t u; } vm, vs; vm.d=m; vs.d=s;
                                            vm.u = (vm.u & 0x7fffffffffffffffULL) | (vs.u & 0x8000000000000000ULL); return vm.d; }
API int    d_expo(double x)      { union { double d; uint64_t u; } v; v.d = x; return (int)((v.u >> 52) & 0x7ff) - 1023; }

int main(void) { return 0; }
