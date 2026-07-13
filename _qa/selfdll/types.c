/* Type-challenge DLL: every return type and param type the recoverer must model
 * (void, char/uchar, short/ushort, int/uint, long long/ull, float, double,
 * pointers of each, pointer returns, struct-by-ptr, mixed-width arithmetic). */
#include <stdint.h>
#define API __declspec(dllexport)

/* return-type coverage */
API void            t_void(int *p)            { *p = *p + 1; }
API signed char     t_char(int x)             { return (signed char)(x * 3); }
API unsigned char   t_uchar(int x)            { return (unsigned char)(x & 0xFF); }
API short           t_short(int x)            { return (short)(x - 1000); }
API unsigned short  t_ushort(int x)           { return (unsigned short)(x * 7); }
API int             t_int(int x)              { return x * x - 1; }
API unsigned int    t_uint(int x)             { return (unsigned int)x >> 1; }
API long long       t_ll(int x)               { return (long long)x * 1000000007LL; }
API unsigned long long t_ull(int x)           { return (unsigned long long)(unsigned int)x * 0x100000001ULL; }
API float           t_float(int x)            { return x * 0.5f; }
API double          t_double(int x)           { return x / 3.0; }

/* pointer params + pointer returns */
API int            *t_intptr(int *a, int i)   { return &a[i]; }
API char           *t_charptr(char *s, int i) { return s + i; }
API const void     *t_voidptr(const int *a)   { return (const void *)a; }
API long long       t_deref_ll(const long long *p) { return *p + 1; }

/* width-mixing arithmetic (sign/zero extension traps) */
API long long       mix_widen(char c, short s, int i) { return (long long)c + s + i; }
API int             mix_narrow(long long x)   { return (int)(x & 0xFFFFFFFF); }
API unsigned        mix_shift(unsigned x, int n) { return x >> (n & 31); }
API int             sext_byte(const char *p)  { return (int)p[0] + (int)p[1]; }   /* movsx */
API unsigned        zext_byte(const unsigned char *p) { return (unsigned)p[0] + p[1]; } /* movzx */

/* struct by pointer — mixed field types */
typedef struct { char c; int i; long long ll; float f; double d; } Mixed;
API long long       mixed_read(const Mixed *m) { return m->c + m->i + m->ll + (long long)m->f + (long long)m->d; }
API void            mixed_write(Mixed *m, int base) { m->c = (char)base; m->i = base*2; m->ll = base*3LL; m->f = base*1.5f; m->d = base/4.0; }

/* bool-ish + ternary chains */
API int             t_bool(int a, int b)      { return (a > b) && (a > 0); }
API int             t_select(int x)           { return x < 0 ? -x : (x > 100 ? 100 : x); }

int main(void) { return 0; }
