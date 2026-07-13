#include <stdbool.h>
/* mix_narrow @ 0x1010  size=3 */
int mix_narrow(int a1) {
    return a1;
}


/* mix_shift @ 0x1020  size=11 */
unsigned int mix_shift(unsigned int a1, int a2) {
    return (unsigned int)(a1) >> (a2 & 0x1f);
}


/* mix_widen @ 0x1030  size=18 */
long long mix_widen(int a1, int a2, int a3) {
    return (long long)((signed char)a1) + (long long)((short)a2) + (long long)a3;
}


/* mixed_read @ 0x1050  size=31 */
long long mixed_read(long long*a1) {
    return (long long)((int)*(signed char*)a1 + *(int*)((char*)a1 + 4)) + (long long)*(double*)((char*)a1 + 0x18) + (long long)*(float*)((char*)a1 + 0x10) + *(long long*)((char*)a1 + 8);
}


/* mixed_write @ 0x1070  size=61 */
void mixed_write(long long*a1, int a2) {
    *(int*)((char*)a1 + 4) = (int)(a2 + a2);
    *(signed char*)a1 = (signed char)a2;
    *(long long*)((char*)a1 + 8) = (long long)a2 + (long long)a2 * 2;
    *(double*)((char*)a1 + 0x18) = (double)a2 * 0.25;
    *(float*)((char*)a1 + 0x10) = (float)a2 * 1.5f;
    return;
}


/* sext_byte @ 0x10b0  size=10 */
int sext_byte(signed char*a1) {
    return (int)a1[1] + (int)*a1;
}


/* t_bool @ 0x10c0  size=17 */
int t_bool(int a1, int a2) {
    if (a1 <= a2 || a1 <= 0) {
        return 0;
    }
    return 1;
}


/* t_char @ 0x10e0  size=8 */
unsigned char t_char(int a1) {
    return (unsigned long long)(((unsigned long long)((signed char)a1 + (unsigned int)((unsigned char)a1)) & 0xff) + a1) & 0xff;
}


/* t_charptr @ 0x10f0  size=7 */
long long t_charptr(long long a1, int a2) {
    return (long long)a2 + a1;
}


/* t_deref_ll @ 0x1100  size=7 */
long long t_deref_ll(long long*a1) {
    return *a1 + 1;
}


/* t_double @ 0x1110  size=17 */
double t_double(int a1) {
    return (double)a1 / 3.0;
}


/* t_float @ 0x1130  size=16 */
float t_float(int a1) {
    return (float)a1 * 0.5f;
}


/* t_int @ 0x1140  size=7 */
int t_int(int a1) {
    return (int)(a1 * a1 + -1);
}


/* t_intptr @ 0x1150  size=8 */
long long t_intptr(long long a1, int a2) {
    return a1 + (long long)a2 * 4;
}


/* t_ll @ 0x1160  size=11 */
long long t_ll(int a1) {
    return (long long)a1 * 0x3b9aca07;
}


/* t_select @ 0x1170  size=22 */
int t_select(int a1) {
    if (a1 >= 0) {
        return a1 > 0x64 ? 0x64 : a1;
    }
    return -a1;
}


/* t_short @ 0x1190  size=9 */
unsigned int t_short(int a1) {
    return (int)(0xffff0000LL | ((unsigned long long)(-1000 + a1) & 0xffff));
}


/* t_uchar @ 0x11a0  size=4 */
unsigned char t_uchar(int a1) {
    return (unsigned char)a1;
}


/* t_uint @ 0x11b0  size=5 */
unsigned int t_uint(unsigned int a1) {
    return (unsigned int)(a1) >> 1;
}


/* t_ull @ 0x11c0  size=17 */
unsigned long long t_ull(int a1) {
    return (unsigned int)a1 * 0x100000001LL;
}


/* t_ushort @ 0x11e0  size=7 */
unsigned int t_ushort(int a1) {
    return (unsigned int)((unsigned short)a1) * 7;
}


/* t_void @ 0x11f0  size=3 */
void t_void(int*a1) {
    *a1 = *a1 + 1;
    return;
}


/* t_voidptr @ 0x1200  size=4 */
long long t_voidptr(long long a1) {
    return a1;
}


/* zext_byte @ 0x1210  size=10 */
unsigned int zext_byte(unsigned char*a1) {
    return (unsigned int)a1[1] + (unsigned int)*a1;
}


