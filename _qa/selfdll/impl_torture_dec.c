#include <stdbool.h>
/* add6 @ 0x1000  size=18 */
int add6(int a1, int a2, int a3, int a4, int a5, int a6) {
    return (int)(a1 + a2) + a3 + a4 + a5 + a6;
}


/* add8 @ 0x1020  size=51 */
long long add8(long long a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) {
    return (long long)a8 + ((long long)a7 + a1 + ((long long)a2 + (long long)a3 + (long long)a4 + (long long)a5 + (long long)a6));
}


/* asr @ 0x1060  size=7 */
int asr(int a1, int a2) {
    return a1 >> a2;
}


/* asr_const @ 0x1070  size=6 */
int asr_const(int a1) {
    return a1 >> 2;
}


/* cas_add @ 0x1080  size=20 */
int cas_add(int*a1, int a2) {
    int t45;
    int t46;
    long long t48;

    while (true) {
        t45 = *a1;
        t46 = *a1;
        t48 = *a1 + a2;
        *a1 = t45 == t46 ? (int)(*a1 + a2) : t46;
        if (t45 == t46) break;
    }
    return (int)t48;
}


/* fwd6 @ 0x10a0  size=32 */
int fwd6(long long a1, long long a2, long long a3, long long a4, int a5, int a6) {
    int t1;

    t1 = add6(a1, a2, a3, a4, a5, a6);
    return t1 + t1;
}


/* fwd8 @ 0x10c0  size=59 */
long long fwd8(int a1, long long a2, long long a3, long long a4, int a5, int a6, int a7, int a8) {
    long long t1;

    t1 = add8((long long)a1, a2, a3, a4, a5, a6, a7, a8);
    return t1 + 0x64;
}


/* g_helper @ 0x1100  size=10 */
int g_helper(int a1) {
    return (int)(a1 * 2 + 1) + a1;
}


/* lsr @ 0x1110  size=7 */
unsigned int lsr(unsigned int a1, int a2) {
    return (unsigned int)(a1) >> a2;
}


/* poison5 @ 0x1130  size=32 */
unsigned long long poison5(long long a1) {
    long long t1;

    t1 = a1 * 0x1cccccccdLL;
    return ((int)((unsigned long long)(t1) >> 0x20) & 1) + ((unsigned long long)(t1) >> 0x22);
}


/* rotloop @ 0x1150  size=57 */
int rotloop(int a1, int a2) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    int t5;

    t3 = a2;
    t4 = 0;
    if (((signed char)a1 & 1) == 0) {
        t1 = a2;
        t2 = 0;
L_1160:;
        t5 = (int)t1 + (int)t2 * 7;
        t3 = t5;
        t4 = t2;
        if (t5 > 0xf4240) {
            return (int)t1 + (int)t2 * 7;
        }
    }
    t1 = ((int)t3 ^ (int)(t4 * 3)) & 0x3fffff;
    t2 = (int)t4 + 1;
    if (t2 >= a1) {
        return (int)((((int)t3 ^ (int)(t4 * 3)) & 0x3fffff) + 0x64);
    }
    goto L_1160;
}


/* sdiv @ 0x1190  size=27 */
long long sdiv(long long a1) {
    return a1 / 7;
}


/* sdiv100 @ 0x11b0  size=18 */
int sdiv100(int a1) {
    return a1 / 0x64;
}


/* sdiv32 @ 0x11d0  size=20 */
int sdiv32(int a1) {
    return a1 / 7;
}


/* sdivn7 @ 0x11f0  size=27 */
long long sdivn7(long long a1) {
    return a1 / -7;
}


/* slen @ 0x1210  size=28 */
int slen(signed char*a1) {
    long long t1;
    signed char*t2;
    long long t3;

    t3 = 0;
    if (*a1 == 0) {
        return (int)t3;
    }
    t1 = 0;
    t2 = a1;
    while (true) {
        t2 = t2 + 1;
        t3 = (int)t1 + 1;
        t1 = (int)t1 + 1;
        if (*t2 == 0) break;
    }
    return (int)t3;
}


/* smod @ 0x1230  size=37 */
long long smod(long long a1) {
    return a1 % 7;
}


/* smod32 @ 0x1260  size=27 */
int smod32(int a1) {
    return a1 % 7;
}


/* stack_arr @ 0x1280  size=89 */
int stack_arr(int a1) {
    char s1[64];
    long long t1;
    long long t2;
    long long t3;
    int t4;

    *(long long*)s1 = 0x1800000003LL;
    *(long long*)((char*)s1 + 8) = 0x300000002bLL;
    *(long long*)((char*)s1 + 0x10) = 0x800000013LL;
    *(long long*)((char*)(s1 + 0x10) + 8) = 0x200000003bLL;
    *(long long*)((char*)s1 + 0x20) = 0x3800000023LL;
    *(long long*)((char*)(s1 + 0x20) + 8) = 0x100000000bLL;
    *(long long*)((char*)s1 + 0x30) = 0x2800000033LL;
    *(long long*)((char*)(s1 + 0x30) + 8) = 0x1b;
    t1 = 0;
    t2 = 0;
    t3 = 0;
    if (a1 > 0) {
        while (true) {
            t3 = t2;
            if ((unsigned int)((int)t1) >= (unsigned int)(0x10)) break;
            t4 = *(int*)((char*)s1 + (t1 * 4));
            t3 = (int)t2 + t4;
            t2 = (int)t2 + t4;
            t1 = (int)t1 + 1;
            if (t1 >= a1) {
                return (int)(t3 + 3);
            }
        }
    }
    return (int)(t3 + 3);
}


/* sum_until_zero @ 0x12e0  size=28 */
int sum_until_zero(int*a1) {
    long long t1;
    int*t2;
    long long t3;

    t3 = 0;
    if (*a1 == 0) {
        return (int)t3;
    }
    t1 = 0;
    t2 = a1;
    while (true) {
        t3 = (int)t1 + *t2;
        t1 = (int)t1 + *t2;
        t2 = (int*)((char*)t2 + 4);
        if (*t2 == 0) break;
    }
    return (int)t3;
}


/* tail_phi @ 0x1300  size=24 */
int tail_phi(int a1, int a2) {
    return g_helper((unsigned int)(a1 + (a2 == 0 ? -10 : 0xa)));
}


/* udiv10 @ 0x1320  size=21 */
unsigned long long udiv10(long long a1) {
    return (unsigned long long)(a1) / (unsigned long long)(0xa);
}


/* udiv3 @ 0x1340  size=12 */
unsigned int udiv3(int a1) {
    return (unsigned int)(a1) / (unsigned int)(3);
}


/* udiv7 @ 0x1350  size=18 */
unsigned int udiv7(int a1) {
    return (unsigned int)(a1) / (unsigned int)(7);
}


/* umod7 @ 0x1370  size=26 */
unsigned int umod7(int a1) {
    return (unsigned int)(a1) % (unsigned int)(7);
}


