#include <stdbool.h>
/* dadd @ 0x1000  size=5 */
double dadd(double a1, double a2) {
    return a1 + a2;
}


/* dmax @ 0x1010  size=5 */
double dmax(double a1, double a2) {
    return a1 > a2 ? a1 : a2;
}


/* dmul @ 0x1020  size=5 */
double dmul(double a1, double a2) {
    return a1 * a2;
}


/* dot2 @ 0x1030  size=23 */
float dot2(float*a1, float*a2) {
    return *(float*)((char*)a1 + 4) * *(float*)((char*)a2 + 4) + *a1 * *a2;
}


/* dot3 @ 0x1050  size=37 */
float dot3(float*a1, float*a2) {
    return *(float*)((char*)a1 + 4) * *(float*)((char*)a2 + 4) + *a1 * *a2 + *(float*)((char*)a1 + 8) * *(float*)((char*)a2 + 8);
}


/* dpoly @ 0x1080  size=47 */
double dpoly(double a1) {
    return ((a1 * 3.0 + 2.0) * a1 + 1.0) * a1 - 5.0;
}


/* f2i @ 0x10b0  size=5 */
int f2i(float a1) {
    return a1;
}


/* fabsf_ @ 0x10c0  size=8 */
#ifndef __DS_FABS_DEFINED
#define __DS_FABS_DEFINED
static double __fabs(double x){ return x<0.0?-x:x; }
static float __fabsf(float x){ return x<0.0f?-x:x; }
#endif
float fabsf_(float a1) {
    return __fabsf(a1);
}


/* fadd @ 0x10d0  size=5 */
float fadd(float a1, float a2) {
    return a1 + a2;
}


/* favg @ 0x10e0  size=13 */
float favg(float a1, float a2) {
    return (a1 + a2) * 0.5f;
}


/* fclamp @ 0x10f0  size=17 */
float fclamp(float a1, float a2, float a3) {
    if (!(a2 > a1)) {
        return a3 < a1 ? a3 : a1;
    }
    return a2;
}


/* fclass @ 0x1110  size=30 */
int fclass(float a1) {
    if (a1 < 0.0f) {
        return -1;
    }
    if (a1 != 0.0f) {
        return 1;
    }
    return 0;
}


/* fdiv @ 0x1130  size=19 */
float fdiv(float a1, float a2) {
    if (a2 != 0.0f) {
        return a1 / a2;
    }
    return 0.0f;
}


/* fgt @ 0x1150  size=9 */
unsigned char fgt(float a1, float a2) {
    return (signed char)(a1 > a2);
}


/* flerp @ 0x1160  size=16 */
float flerp(float a1, float a2, float a3) {
    return (a2 - a1) * a3 + a1;
}


/* fmax3 @ 0x1170  size=9 */
float fmax3(float a1, float a2, float a3) {
    int t1;
    float t2;

    t1 = a1 > a2;
    t2 = t1 ? a1 : a2;
    return t2 > a3 ? t2 : a3;
}


/* fmaxarr @ 0x1180  size=116 */
float fmaxarr(float*a1, int a2) {
    long long t1;
    float t2;
    long long t3;
    float t4;
    float t5;
    long long t7;
    long long t8;
    long long t9;
    long long t10;
    long long t11;
    long long t12;
    int t13;
    float t14;
    int t15;
    float t16;
    int t17;
    float t18;
    long long t19;
    long long t20;
    long long t21;
    int t6;

    t5 = *a1;
    if (a2 <= 1) {
        return t5;
    }
    t3 = 1;
    t4 = *a1;
    if ((int)(a2 + -1) >= 4) {
        t1 = 1;
        t2 = *a1;
        while (true) {
            t7 = (long long)((int)t1);
            t8 = t7 * 4;
            t9 = (char*)a1 + t8;
            t10 = t9 + 0xc;
            t11 = t9 + 8;
            t12 = t9 + 4;
            t13 = *(float*)t9 > t2;
            t14 = t13 ? *(float*)t9 : t2;
            t15 = *(float*)t12 > t14;
            t16 = t15 ? *(float*)t12 : t14;
            t17 = *(float*)t11 > t16;
            t18 = t17 ? *(float*)t11 : t16;
            t2 = *(float*)t10 > t18 ? *(float*)t10 : t18;
            t1 = (int)t1 + 4;
            if (t1 >= (int)(a2 + -3)) break;
        }
        t3 = t1;
        t4 = t2;
        t5 = t2;
        if (t1 >= a2) {
            return t5;
        }
    }
    while (true) {
        t19 = (long long)((int)t3);
        t20 = t19 * 4;
        t21 = (char*)a1 + t20;
        t4 = *(float*)t21 > t4 ? *(float*)t21 : t4;
        t6 = t3;
        t3 = (int)t3 + 1;
        if ((int)t6 + 1 >= a2) break;
    }
    return t4;
}


/* fmul @ 0x1200  size=5 */
float fmul(float a1, float a2) {
    return a1 * a2;
}


/* frelu @ 0x1210  size=8 */
float frelu(float a1) {
    return a1 > 0.0f ? a1 : 0.0f;
}


/* fsign @ 0x1220  size=25 */
int fsign(float a1) {
    if (!(a1 > 0.0f)) {
        return (int)(!(a1 < 0.0f)) - 1;
    }
    return 1;
}


/* fsub @ 0x1240  size=5 */
float fsub(float a1, float a2) {
    return a1 - a2;
}


/* fsum @ 0x1250  size=73 */
float fsum(float*a1, int a2) {
    long long t1;
    float t2;
    long long t3;
    float t4;
    long long t5;
    float t6;
    float t7;
    long long t8;
    long long t9;
    long long t10;
    long long t11;
    long long t12;
    long long t13;
    float t14;

    t5 = 0;
    t6 = 0.0f;
    if (a2 >= 4) {
        t1 = 0;
        t2 = 0.0f;
        while (true) {
            t5 = (int)t1 + 4;
            t8 = (long long)((int)t1);
            t9 = t8 * 4;
            t10 = (char*)a1 + t9;
            t6 = t2 + *(float*)t10 + *(float*)((char*)t10 + 4) + *(float*)((char*)t10 + 8) + *(float*)((char*)t10 + 0xc);
            t11 = (long long)((int)t1);
            t12 = t11 * 4;
            t13 = (char*)a1 + t12;
            t2 = t2 + *(float*)t13 + *(float*)((char*)t13 + 4) + *(float*)((char*)t13 + 8) + *(float*)((char*)t13 + 0xc);
            t1 = (int)t1 + 4;
            if (t1 >= (int)(a2 + -3)) break;
        }
    }
    t3 = t5;
    t4 = t6;
    t7 = t6;
    if ((int)t5 >= a2) {
        return t7;
    }
    while (true) {
        t14 = a1[t3];
        t7 = t4 + t14;
        t4 = t4 + t14;
        t3 = (int)t3 + 1;
        if (t3 >= a2) break;
    }
    return t7;
}


/* i2d @ 0x12a0  size=9 */
double i2d(int a1) {
    return (double)a1;
}


/* i2f @ 0x12b0  size=8 */
float i2f(int a1) {
    return a1;
}


/* len2sq @ 0x12c0  size=22 */
float len2sq(float*a1) {
    long long t1;

    t1 = (char*)a1 + 4;
    return *(float*)t1 * *(float*)t1 + *a1 * *a1;
}


/* scale_int @ 0x12f0  size=12 */
float scale_int(int a1, float a2) {
    return a1 * a2;
}


/* vscale2 @ 0x1300  size=16 */
void vscale2(double*a1, float a2) {
    return;
}


