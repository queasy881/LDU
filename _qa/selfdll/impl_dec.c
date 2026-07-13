#include <stdbool.h>
static int dword_19000 = 2;
/* classify @ 0x1000  size=49 */
int classify(int a1) {
    if (a1 == 0) {
        return 0x64;
    }
    if (a1 - 1 == 0) {
        return 0xc8;
    }
    if (a1 - 1 - 1 == 0) {
        return 0x12c;
    }
    if (a1 - 1 - 1 == 5) {
        return 0x2bc;
    }
    return -1;
}


/* count_bit @ 0x1040  size=35 */
unsigned int count_bit(unsigned int a1) {
    unsigned long long t1;
    unsigned long long t2;
    unsigned long long t3;
    int t5;
    unsigned int t4;

    t3 = 0;
    if (a1 == 0) {
        return (int)t3;
    }
    t1 = 0;
    t2 = a1;
    while (true) {
        t5 = (int)t2 & 1;
        t3 = (int)t1 + t5;
        t1 = (int)t1 + t5;
        t4 = t2;
        t2 = (unsigned int)((int)t2) >> 1;
        if ((unsigned int)((int)t4) < (unsigned int)(2)) break;
    }
    return (int)t3;
}


/* deref_off @ 0x1070  size=11 */
int deref_off(int*a1, int a2) {
    long long t1;
    long long t2;

    t1 = (long long)a2 * 4;
    t2 = (char*)a1 + t1;
    return *(int*)((char*)t2 + 4) + *(int*)t2;
}


/* dmax @ 0x1080  size=5 */
double dmax(double a1, double a2) {
    return a1 > a2 ? a1 : a2;
}


/* dot @ 0x1090  size=273 */
int dot(int*a1, int*a2, int a3) {
    long long t1;
    long long t2;
    long long t4;
    long long t5;
    long long t6;
    long long t7;
    long long t8;
    long long t9;
    long long t10;
    long long t11;
    long long t12;
    long long t13;
    long long t14;
    long long t15;
    long long t16;
    long long t17;
    long long t18;
    long long t19;
    long long t20;
    long long t21;

    t15 = 0;
    if (a3 <= 0) {
        return (int)t15;
    }
    t7 = 0;
    t8 = 0;
    if ((unsigned int)(a3) < (unsigned int)(8)) {
L_112c:;
        t9 = t7;
        t10 = 0;
        t11 = 0;
        if (a3 - (int)t7 < 2) {
            t20 = (long long)((int)t9);
            t21 = t20 * 4;
            t12 = (int)t8 + *(int*)((char*)a1 + t21) * *(int*)((char*)a2 + t21);
            t13 = t10;
            t14 = t11;
            return (int)(t14 + t13) + (int)t12;
        }
        t4 = t7;
        t5 = 0;
        t6 = 0;
        while (true) {
            t16 = (long long)((int)t4);
            t17 = t16 * 4;
            t5 = (int)t5 + *(int*)((char*)a1 + t17) * *(int*)((char*)a2 + t17);
            t18 = (long long)((int)t4);
            t19 = t18 * 4;
            t6 = (int)t6 + *(int*)((char*)((char*)a2 + t19) + 4) * *(int*)((char*)((char*)a1 + t19) + 4);
            t4 = (int)t4 + 2;
            if (t4 >= (int)(a3 + -1)) break;
        }
        t9 = t4;
        t10 = t5;
        t11 = t6;
        t12 = t8;
        t13 = t5;
        t14 = t6;
        if (t4 >= a3) {
            return (int)(t14 + t13) + (int)t12;
        }
        t20 = (long long)((int)t9);
        t21 = t20 * 4;
        t12 = (int)t8 + *(int*)((char*)a1 + t21) * *(int*)((char*)a2 + t21);
        t13 = t10;
        t14 = t11;
        return (int)(t14 + t13) + (int)t12;
    }
    t7 = 0;
    t8 = 0;
    if (dword_19000 < 2) goto L_112c;
    t1 = 0;
    t2 = 0;
    while (true) {
        t1 = (int)t1 + 8;
        if (t1 >= (a3 & 0xfffffff8)) break;
    }
    t7 = t1;
    t8 = t2;
    t15 = t2;
    if (t1 >= a3) {
        return (int)t15;
    }
    goto L_112c;
}


/* favg @ 0x11b0  size=13 */
float favg(float a1, float a2) {
    return (a1 + a2) * 0.5f;
}


/* find_max @ 0x11c0  size=42 */
int* find_max(int*a1, int a2) {
    int*t1;
    long long t2;
    int*t4;
    long long t6;
    long long t7;
    long long t5;

    t4 = a1;
    if (a2 <= 1) {
        return t4;
    }
    t1 = a1;
    t2 = 1;
    while (true) {
        t6 = (int)t2 * 4;
        t7 = (char*)a1 + t6;
        t5 = *(int*)t7 > *t1 ? t7 : t1;
        t1 = (int*)t5;
        t2 = (int)t2 + 1;
        t4 = (int*)t5;
        if (t2 >= a2) break;
    }
    return t4;
}


/* frelu @ 0x11f0  size=8 */
float frelu(float a1) {
    return a1 > 0.0f ? a1 : 0.0f;
}


/* fwd_add @ 0x1200  size=4 */
int fwd_add(int a1, int a2) {
    return (int)(a1 + a2);
}


/* mat_trace @ 0x1220  size=98 */
int mat_trace(int*a1, int a2) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    long long t5;
    long long t6;
    long long t7;
    int t8;
    int t9;

    t4 = 0;
    t5 = 0;
    t6 = 0;
    t9 = (int)(a2 + 1);
    if (a2 >= 2) {
        t1 = 0;
        t2 = 0;
        t3 = 0;
        while (true) {
            t8 = t9;
            t2 = (int)t2 + a1[(t8 * (int)t1)];
            t3 = (int)t3 + a1[((int)(t1 + 1) * t8)];
            t1 = (int)t1 + 2;
            if (t1 >= (int)(a2 + -1)) break;
        }
        t4 = t1;
        t5 = t2;
        t6 = t3;
    }
    t7 = 0;
    if ((int)t4 >= a2) {
        return (int)(t6 + t5) + (int)t7;
    }
    t7 = a1[(t9 * (int)t4)];
    return (int)(t6 + t5) + (int)t7;
}


/* my_abs @ 0x1290  size=8 */
int my_abs(int a1) {
    int t1;

    t1 = 0 - a1 < 0 ? a1 : -a1;
    return t1;
}


/* my_clamp @ 0x12a0  size=17 */
int my_clamp(int a1, int a2, int a3) {
    if (a1 >= a2) {
        return a1 > a3 ? a3 : a1;
    }
    return a2;
}


/* my_fib @ 0x12c0  size=57 */
int my_fib(int a1) {
    int t3;
    int t4;

    if (a1 >= 2) {
        t3 = my_fib(a1 + -2);
        t4 = my_fib(a1 + -1);
        return t4 + t3;
    }
    return a1;
}


/* my_gcd @ 0x1300  size=35 */
int my_gcd(int a1, int a2) {
    int t1;
    long long t2;
    long long t3;
    int t4;

    t3 = a1;
    if (a2 == 0) {
        return (int)t3;
    }
    t1 = a1;
    t2 = a2;
    while (true) {
        t3 = (int)t2;
        t4 = t1;
        t1 = (int)t2;
        t2 = (int)t4 % (int)t2;
        if (t2 == 0) break;
    }
    return (int)t3;
}


/* my_max @ 0x1330  size=8 */
int my_max(int a1, int a2) {
    return a1 > a2 ? a1 : a2;
}


/* my_mul @ 0x1340  size=6 */
int my_mul(int a1, int a2) {
    return a1 * a2;
}


/* my_strlen @ 0x1350  size=28 */
int my_strlen(signed char*a1) {
    long long t1;
    long long t2;

    t2 = 0;
    if (*a1 == 0) {
        return (int)t2;
    }
    t1 = 0;
    while (true) {
        t2 = (int)t1 + 1;
        t1 = (int)t1 + 1;
        if (a1[t1] == 0) break;
    }
    return (int)t2;
}


/* my_sub @ 0x1370  size=5 */
int my_sub(int a1, int a2) {
    return a1 - a2;
}


/* my_swap @ 0x1380  size=11 */
void my_swap(int*a1, int*a2) {
    int t1;

    t1 = *a1;
    *a1 = *a2;
    *a2 = t1;
    return;
}


/* poly @ 0x1390  size=39 */
long long poly(int a1) {
    return (((((long long)a1 + ((long long)a1 + 1) * 4) * (long long)a1 + 3) * (long long)a1 + 2) * (long long)a1 + 1) * (long long)a1;
}


/* rec_bump @ 0x13c0  size=15 */
void rec_bump(int*a1, int a2) {
    *a1 = *a1 + a2;
    *(int*)((char*)a1 + 4) = *(int*)((char*)a1 + 4) + a2;
    *(int*)((char*)a1 + 8) = *(int*)((char*)a1 + 8) + a2;
    *(int*)((char*)a1 + 0xc) = *(int*)((char*)a1 + 0xc) + a2;
    *(int*)((char*)a1 + 0x10) = *(int*)((char*)a1 + 0x10) + a2;
    return;
}


/* rec_sum @ 0x13d0  size=15 */
int rec_sum(int*a1) {
    return *(int*)((char*)a1 + 0x10) + *(int*)((char*)a1 + 0xc) + *(int*)((char*)a1 + 8) + *(int*)((char*)a1 + 4) + *a1;
}


/* reverse_bits @ 0x13e0  size=46 */
unsigned int reverse_bits(unsigned int a1) {
    unsigned long long t1;
    unsigned long long t2;
    long long t3;
    int t5;
    int t6;
    int t7;

    t1 = 0;
    t2 = a1;
    t3 = 0x10;
    while (true) {
        t5 = (int)t2 & 1;
        t6 = (int)t1 + (int)t1;
        t7 = t6 | t5;
        t1 = (t7 + t7) | (((unsigned int)((int)t2) >> 1) & 1);
        t2 = (unsigned int)((int)t2) >> 2;
        t3 = (int)t3 - 1;
        if (t3 == 0) break;
    }
    return t1;
}


/* seq_two @ 0x1410  size=28 */
void seq_two(int*a1) {
    *a1 = 7;
    *(int*)((char*)a1 + 4) = 7;
    *(int*)((char*)a1 + 8) = 9;
    *(int*)((char*)a1 + 0xc) = 9;
    return;
}


/* set_range @ 0x1430  size=26 */
void __stosb(unsigned char*, unsigned char, unsigned long long);
void __stosw(unsigned short*, unsigned short, unsigned long long);
void __stosd(unsigned long*, unsigned long, unsigned long long);
void __stosq(unsigned long long*, unsigned long long, unsigned long long);
void set_range(long long a1, int a2, int a3) {
    if (a2 <= 0) {
        return;
    }
    __stosd(a1, (int)((long long)a3), (long long)a2);
    return;
}


/* str_eq @ 0x1450  size=74 */
unsigned char str_eq(signed char*a1, unsigned char*a2) {
    unsigned char*t1;
    unsigned char*t2;
    unsigned long long t3;
    unsigned long long t4;

    if (*a1 == 0) {
        t3 = 0;
        t4 = (unsigned int)*a2;
        return (signed char)((signed char)t3 == (signed char)t4);
    }
    t1 = (unsigned char*)a1;
    t2 = a2;
    while (true) {
        t3 = (unsigned int)*t1;
        t4 = (unsigned int)*t2;
        if ((signed char)*t1 != (signed char)*t2) break;
        t1 = t1 + 1;
        t2 = t2 + 1;
        if ((signed char)*t1 == 0) {
            return (signed char)((signed char)*t1 == (signed char)*t2);
        }
    }
    return (signed char)((signed char)t3 == (signed char)t4);
}


/* sum_array @ 0x14a0  size=188 */
long long sum_array(int*a1, int a2) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    long long t5;
    long long t6;
    long long t7;
    long long t8;
    long long t9;
    long long t10;
    long long t11;
    long long t12;
    long long t13;
    long long t14;
    long long t15;
    long long t16;
    long long t17;
    long long t18;
    long long t19;
    long long t20;

    t15 = 0;
    if (a2 <= 0) {
        return t15;
    }
    t7 = 0;
    t8 = 0;
    if ((unsigned int)(a2) < (unsigned int)(4)) {
L_150b:;
        t9 = t7;
        t10 = 0;
        t11 = 0;
        if (a2 - (int)t7 < 2) {
            t12 = t8 + (long long)a1[t9];
            t13 = t10;
            t14 = t11;
            return t14 + t13 + t12;
        }
        t4 = t7;
        t5 = 0;
        t6 = 0;
        while (true) {
            t20 = (char*)a1 + (long long)((int)t4) * 4;
            t5 = t5 + (long long)*(int*)t20;
            t6 = t6 + (long long)*(int*)((char*)t20 + 4);
            t4 = (int)t4 + 2;
            if (t4 >= (int)(a2 + -1)) break;
        }
        t9 = t4;
        t10 = t5;
        t11 = t6;
        t12 = t8;
        t13 = t5;
        t14 = t6;
        if (t4 >= a2) {
            return t14 + t13 + t12;
        }
        t12 = t8 + (long long)a1[t9];
        t13 = t10;
        t14 = t11;
        return t14 + t13 + t12;
    }
    t7 = 0;
    t8 = 0;
    if (dword_19000 < 2) goto L_150b;
    t1 = 0;
    t2 = 0;
    t3 = 0;
    t16 = 0;
    t17 = 0;
    while (true) {
        t18 = (char*)a1 + (long long)((int)t1) * 4;
        t2 = t2 + (long long)*(int*)((char*)t18 + 8);
        t3 = t3 + (long long)*(int*)t18;
        t16 = t16 + (long long)*(int*)((char*)t18 + 0xc);
        t17 = t17 + (long long)*(int*)((char*)t18 + 4);
        t1 = (int)t1 + 4;
        if (t1 >= (a2 & 0xfffffffc)) break;
    }
    t7 = t1;
    t19 = t2 + t3 + (t16 + t17);
    t8 = t19;
    t15 = t19;
    if (t1 >= a2) {
        return t15;
    }
    goto L_150b;
}


/* sum_to @ 0x1560  size=62 */
int sum_to(int a1) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    long long t5;
    long long t6;
    int t8;

    t4 = 1;
    t5 = 0;
    t6 = 0;
    if (a1 < 2) {
        t8 = (int)t4 > a1 ? 0 : (int)t4;
        return (int)(t6 + t5) + t8;
    }
    t1 = 1;
    t2 = 0;
    t3 = 0;
    while (true) {
        t4 = (int)t1 + 2;
        t5 = (int)t2 + (int)t1;
        t2 = (int)t2 + (int)t1;
        t6 = (int)t3 + 1 + (int)t1;
        t3 = (int)t3 + 1 + (int)t1;
        t1 = (int)t1 + 2;
        if (t1 > (int)(a1 + -1)) break;
    }
    t8 = (int)t4 > a1 ? 0 : (int)t4;
    return (int)(t6 + t5) + t8;
}


/* vec4_scale @ 0x15a0  size=69 */
void vec4_scale(int*a1, int a2) {
    long long t1;

    if (dword_19000 >= 2) {
        *a1 = *a1 * a2;
        *(int*)((char*)a1 + 4) = *(int*)((char*)a1 + 4) * a2;
        *(int*)((char*)a1 + 8) = *(int*)((char*)a1 + 8) * a2;
        *(int*)((char*)a1 + 0xc) = *(int*)((char*)a1 + 0xc) * a2;
        return;
    }
    t1 = 0;
    while (true) {
        a1[t1] = a2 * a1[t1];
        t1 = t1 + 1;
        if (t1 == 4) break;
    }
    return;
}


/* vec4_sum @ 0x15f0  size=12 */
int vec4_sum(int*a1) {
    return *(int*)((char*)a1 + 0xc) + *(int*)((char*)a1 + 8) + *(int*)((char*)a1 + 4) + *a1;
}


int my_add(int a,int b){return fwd_add(a,b);}
