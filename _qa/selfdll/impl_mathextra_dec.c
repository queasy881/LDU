#include <stdbool.h>
/* d_copysign @ 0x1000  size=63 */
double d_copysign(double a1, double a2) {
    unsigned long long v1;

    v1 = (*(unsigned long long*)(&a2) & -9223372036854775808LL) | (*(unsigned long long*)(&a1) & 0x7fffffffffffffffLL);
    return *(double*)(&v1);
}


/* d_expo @ 0x1040  size=26 */
unsigned int d_expo(double a1) {
    return ((int)((unsigned long long)(*(unsigned long long*)(&a1)) >> 0x34) & 0x7ff) - 0x3ff;
}


/* d_fabs @ 0x1060  size=28 */
double d_fabs(long long a1) {
    a1 = *(long long*)&a1 & 0x7fffffffffffffffLL;
    return *(double*)&a1;
}


/* d_isneg @ 0x1080  size=30 */
unsigned int d_isneg(double a1) {
    return (int)((*(long long*)&a1 & -9223372036854775808LL) != 0);
}


/* d_signbit @ 0x10a0  size=16 */
unsigned long long d_signbit(double a1) {
    return (unsigned long long)(*(unsigned long long*)(&a1)) >> 0x3f;
}


/* dhypot @ 0x10b0  size=24 */
double sqrt(double);
float sqrtf(float);
double dhypot(double a1, double a2) {
    return sqrt(a1 * a1 + a2 * a2);
}


/* fdist @ 0x10d0  size=32 */
double sqrt(double);
float sqrtf(float);
float fdist(float a1, float a2, float a3, float a4) {
    float t1;
    float t2;

    t1 = a2 - a4;
    t2 = a1 - a3;
    return sqrtf(t1 * t1 + t2 * t2);
}


/* fnorm_x @ 0x10f0  size=43 */
double sqrt(double);
float sqrtf(float);
float fnorm_x(float a1, float a2) {
    if (!(sqrtf(a1 * a1 + a2 * a2) > 0.0f)) {
        return 0.0f;
    }
    return a1 / sqrtf(a1 * a1 + a2 * a2);
}


/* vec_len2 @ 0x1130  size=27 */
double sqrt(double);
float sqrtf(float);
float vec_len2(float a1, float a2) {
    return sqrtf(a1 * a1 + a2 * a2);
}


/* vec_len3 @ 0x1150  size=35 */
double sqrt(double);
float sqrtf(float);
float vec_len3(float a1, float a2, float a3) {
    return sqrtf(a1 * a1 + a2 * a2 + a3 * a3);
}


