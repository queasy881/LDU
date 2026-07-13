/* torture.c — exercises the audit's Tier-0 correctness classes so the differential
 * harness (difftest.sh torture) tells us which are REAL bugs vs already-fixed. */
#include <intrin.h>
#define API
#define NOINLINE __declspec(noinline)

/* T0-1: calls with >4 args (5th+ go on the stack in the MS x64 ABI). The
 * forwarders keep the callees non-inlined so a real CALL survives to decompile. */
API NOINLINE int add6(int a,int b,int c,int d,int e,int f){ return a+b+c+d+e+f; }
API NOINLINE long long add8(long long a,int b,int c,int d,int e,int f,int g,int h){
    return a+b+c+d+e+(long long)f+g+h; }
API int fwd6(int a,int b,int c,int d,int e,int f){ return add6(a,b,c,d,e,f)*2; }
API long long fwd8(int a,int b,int c,int d,int e,int f,int g,int h){
    return add8((long long)a,b,c,d,e,f,g,h) + 100; }

/* T0-6: signed (arithmetic) vs unsigned (logical) right shift, incl. negatives. */
API int asr(int x,int n){ return x >> n; }
API unsigned lsr(unsigned x,int n){ return x >> n; }
API int asr_const(int x){ return x >> 2; }         /* -13>>2 == -4 (arith), not 1073741820 */

/* T0-3: sentinel-scan loops (while(*p)) — must NOT become while(1). */
API int slen(const char* p){ int n=0; while(*p){ n++; p++; } return n; }
API int sum_until_zero(const int* p){ int s=0; while(*p){ s+=*p; p++; } return s; }

/* T0-2: interlocked CAS retry loop (concurrency primitive; single-threaded here). */
API long cas_add(volatile long* p,long delta){
    long oldv, newv;
    do { oldv=*p; newv=oldv+delta; } while(_InterlockedCompareExchange(p,newv,oldv)!=oldv);
    return newv;
}

/* T1-7: a single stack array used at many displacements (must stay ONE buffer). */
API int stack_arr(int n){
    int st[16];
    st[0]=3;
    for(int i=1;i<16;i++) st[i]=(st[i-1]*7+3)&0x3f;  /* data-dependent -> not vectorizable */
    int s=0; for(int i=0;i<n && i<16;i++) s+=st[i];
    return s + st[0] + st[15];
}

/* T0-4: tail call whose argument is a phi (v depends on a branch). */
API NOINLINE int g_helper(int x){ return x*3+1; }
API int tail_phi(int x,int c){ int v = c ? x+10 : x-10; return g_helper(v); }

/* extra: 64-bit signed divide/mod (magic-number division) for sanity. */
API long long sdiv(long long a){ return a / 7; }
API long long smod(long long a){ return a % 7; }

/* T4: magic-number division across signedness x width x the add-correction form.
 * Each function's BODY holds the mulhi+shift idiom the recognizer must invert back
 * to `x / C` / `x % C` and stay bit-identical (round-trip verified). */
API NOINLINE int                sdiv32(int x){ return x / 7; }              /* signed32, +x corr */
API NOINLINE int                smod32(int x){ return x % 7; }
API NOINLINE unsigned           udiv3(unsigned x){ return x / 3; }          /* unsigned32, add=0 */
API NOINLINE unsigned           udiv7(unsigned x){ return x / 7; }          /* unsigned32, add=1 */
API NOINLINE unsigned           umod7(unsigned x){ return x % 7; }
API NOINLINE unsigned long long udiv10(unsigned long long x){ return x / 10; } /* unsigned64 */
API NOINLINE long long          sdivn7(long long x){ return x / -7; }        /* negative divisor */
API NOINLINE int                sdiv100(int x){ return x / 100; }            /* larger divisor */

/* T4-poison: a GENUINE 64-bit (x*K)>>32 high-multiply that is NOT a division. K's
 * low 32 bits (0xcccccccd) are the unsigned /5 magic, so a width-blind recognizer
 * would mis-fold `h>>2` to `(unsigned)x / 5` (wrong). The two uses of `h` keep the
 * >>32 shape from merging into one shift so it actually reaches the recognizer. */
API NOINLINE unsigned long long poison5(unsigned long long x){
    unsigned long long h = (x * 0x1cccccccdULL) >> 32;
    return (h >> 2) + (h & 1);
}

/* T-node-split: a `goto` INTO the middle of a loop body makes a genuine two-entry
 * (irreducible) rotated loop — the exact shape MSVC emits for guarded loops (the
 * NullWare goto residue). The node-splitter must render this goto-free AND keep it
 * bit-identical. Two entries: the while top (body_A) and `mid` (body_B). */
API NOINLINE int rotloop(int n, int seed){
    int s = seed, i = 0;
    if ((n & 1) != 0) goto mid;         /* guard entry: skip body_A on the first iteration */
    while (1){
        s = s + i*7;                     /* body_A (early-returns like the real cases) */
        if (s > 1000000) return s;
    mid:
        s = (s ^ (i*3)) & 0x3fffff;      /* body_B (the shared merge) */
        i++;
        if (i >= n) break;
    }
    return s + 100;
}

