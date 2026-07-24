/* Float/double-heavy test DLL: scalar FP math, comparisons, conversions, vec ops. */
#include <stdint.h>
#define API __declspec(dllexport)

API float  fadd(float a, float b)   { return a + b; }
API float  fsub(float a, float b)   { return a - b; }
API float  fmul(float a, float b)   { return a * b; }
API float  fdiv(float a, float b)   { return b != 0.0f ? a / b : 0.0f; }
API float  favg(float a, float b)   { return (a + b) * 0.5f; }
API float  fmax3(float a, float b, float c) { float m = a > b ? a : b; return m > c ? m : c; }
API float  frelu(float x)           { return x > 0.0f ? x : 0.0f; }
API float  fclamp(float x, float lo, float hi) { return x < lo ? lo : (x > hi ? hi : x); }
API float  flerp(float a, float b, float t) { return a + (b - a) * t; }
API float  fabsf_(float x)          { return x < 0.0f ? -x : x; }

API double dadd(double a, double b) { return a + b; }
API double dmul(double a, double b) { return a * b; }
API double dmax(double a, double b) { return a > b ? a : b; }
API double dpoly(double x)          { return ((3.0*x + 2.0)*x + 1.0)*x - 5.0; }  /* Horner */

/* int <-> float conversions */
API int    f2i(float x)             { return (int)x; }
API float  i2f(int x)               { return (float)x; }
API double i2d(int x)               { return (double)x; }
API float  scale_int(int n, float s){ return n * s; }

/* comparisons returning bool/int */
API int    fgt(float a, float b)    { return a > b; }
API int    fsign(float x)           { return x > 0.0f ? 1 : (x < 0.0f ? -1 : 0); }
API int    fclass(float x)          { if (x < 0.0f) return -1; if (x == 0.0f) return 0; return 1; }

/* vec2/vec3 by pointer */
API float  dot2(const float *a, const float *b) { return a[0]*b[0] + a[1]*b[1]; }
API float  dot3(const float *a, const float *b) { return a[0]*b[0] + a[1]*b[1] + a[2]*b[2]; }
API float  len2sq(const float *v)   { return v[0]*v[0] + v[1]*v[1]; }
API void   vscale2(float *v, float s){ v[0] *= s; v[1] *= s; }

/* float array (scalar loop) */
API float  fsum(const float *a, int n) { float s = 0.0f; for (int i=0;i<n;i++) s += a[i]; return s; }
API float  fmaxarr(const float *a, int n) { float m = a[0]; for (int i=1;i<n;i++) if (a[i]>m) m=a[i]; return m; }

int main(void) { return 0; }
