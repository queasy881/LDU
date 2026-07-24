/* SIMD test DLL: loops the /O2 auto-vectorizer turns into SSE (movdqu/pmulld/
 * paddq/mulps/addps + horizontal reductions). Stresses the packed-lane lifting. */
#include <stdint.h>
#define API __declspec(dllexport)

/* element-wise int maps (pmulld / paddd / psubd) */
API void iscale(int *a, int n, int k)         { for (int i=0;i<n;i++) a[i] *= k; }
API void iadd(int *a, const int *b, int n)    { for (int i=0;i<n;i++) a[i] += b[i]; }
API void isub(int *a, const int *b, int n)    { for (int i=0;i<n;i++) a[i] -= b[i]; }
API void iaxpy(int *y, const int *x, int a, int n) { for (int i=0;i<n;i++) y[i] += a*x[i]; }

/* int reductions (paddd/paddq + horizontal reduce) */
API int      isum(const int *a, int n)        { int s=0; for (int i=0;i<n;i++) s+=a[i]; return s; }
API int64_t  isum64(const int *a, int n)      { int64_t s=0; for (int i=0;i<n;i++) s+=a[i]; return s; }
API int      idot(const int *a, const int *b, int n) { int s=0; for (int i=0;i<n;i++) s+=a[i]*b[i]; return s; }
API int      imax(const int *a, int n)        { int m=a[0]; for (int i=1;i<n;i++) if (a[i]>m) m=a[i]; return m; }

/* element-wise float maps (mulps / addps) */
API void fscale(float *a, int n, float k)     { for (int i=0;i<n;i++) a[i] *= k; }
API void fadd_v(float *a, const float *b, int n){ for (int i=0;i<n;i++) a[i] += b[i]; }
API void fsaxpy(float *y, const float *x, float a, int n){ for (int i=0;i<n;i++) y[i] += a*x[i]; }

/* float reductions (addps + horizontal reduce) */
API float    fsumv(const float *a, int n)     { float s=0.0f; for (int i=0;i<n;i++) s+=a[i]; return s; }
API float    fdotv(const float *a, const float *b, int n){ float s=0.0f; for (int i=0;i<n;i++) s+=a[i]*b[i]; return s; }

int main(void) { return 0; }
