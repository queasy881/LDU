#include <stdbool.h>
static int dword_19000 = 0;
/* fadd_v @ 0x1000  size=339 */
void fadd_v(float*a1, float*a2, int a3) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    long long t6;
    long long t7;
    long long t8;
    long long t19;
    long long t20;
    long long t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    long long t37;
    long long t38;
    long long t39;
    long long t40;
    long long t41;
    long long t42;
    long long t43;
    long long t44;
    long long t45;
    long long t46;
    long long t47;
    long long t48;
    long long t49;
    long long t50;
    long long t51;
    long long t52;
    long long t53;
    long long t54;
    long long t55;
    long long t56;
    long long t57;
    long long t58;
    long long t59;
    long long t60;
    long long t61;
    long long t62;
    long long t63;
    long long t64;
    float*t65;
    float*t66;
    float*t67;

    if (a3 <= 0) {
        return;
    }
    t8 = 0;
    if ((unsigned int)(a3) < (unsigned int)(2)) {
L_10d3:;
        t4 = t8;
        if (a3 - (int)t8 >= 4) {
            t3 = t8;
            while (true) {
                t55 = (long long)((int)t3);
                t56 = t55 * 4;
                t67 = (float*)((char*)a1 + (long long)((int)t3) * 4);
                *t67 = *(float*)((char*)a1 + t56) + *(float*)((char*)a2 + t56);
                t57 = (long long)((int)t3);
                t58 = t57 * 4;
                *(float*)((char*)t67 + 4) = *(float*)((char*)((char*)a1 + t58) + 4) + *(float*)((char*)((char*)a2 + t58) + 4);
                t59 = (long long)((int)t3);
                t60 = t59 * 4;
                *(float*)((char*)t67 + 8) = *(float*)((char*)((char*)a1 + t60) + 8) + *(float*)((char*)((char*)a2 + t60) + 8);
                t61 = (long long)((int)t3);
                t62 = t61 * 4;
                *(float*)((char*)t67 + 0xc) = *(float*)((char*)((char*)a1 + t62) + 0xc) + *(float*)((char*)((char*)a2 + t62) + 0xc);
                t3 = (int)t3 + 4;
                if (t3 >= (int)(a3 + -3)) break;
            }
            t4 = t3;
            if (t3 >= a3) {
                return;
            }
        }
        while (true) {
            t63 = (long long)((int)t4);
            t64 = t63 * 4;
            a1[t4] = *(float*)((char*)a1 + t64) + *(float*)((char*)a2 + t64);
            t4 = (int)t4 + 1;
            if (t4 >= a3) break;
        }
        return;
    } else {
        if ((unsigned long long)(a1) > (unsigned long long)((char*)a2 + -4 + (long long)a3 * 4)) {
L_1037:;
            t6 = 0;
            if ((unsigned int)(a3) < (unsigned int)(0x10)) {
L_10a7:;
                t2 = t6;
                while (true) {
                    t51 = (long long)((int)t2);
                    t52 = t51 * 4;
                    t66 = (float*)((char*)a1 + (long long)((int)t2) * 4);
                    *t66 = *(float*)((char*)a1 + t52) + *(float*)((char*)a2 + t52);
                    t53 = (long long)((int)t2);
                    t54 = t53 * 4;
                    *(float*)((char*)t66 + 4) = *(float*)((char*)((char*)a1 + t54) + 4) + *(float*)((char*)((char*)a2 + t54) + 4);
                    t7 = (int)t2 + 2;
                    t2 = (int)t2 + 2;
                    if (t2 >= (a3 & 0xfffffffe)) break;
                }
            } else {
                t1 = 0;
                while (true) {
                    t19 = (long long)((int)t1);
                    t20 = t19 * 4;
                    t65 = (float*)((char*)a1 + (long long)((int)t1) * 4);
                    *t65 = *(float*)((char*)a1 + t20) + *(float*)((char*)a2 + t20);
                    t21 = (long long)((int)t1);
                    t22 = t21 * 4;
                    *(float*)((char*)t65 + 4) = *(float*)((char*)((char*)a1 + t22) + 4) + *(float*)((char*)((char*)a2 + t22) + 4);
                    t23 = (long long)((int)t1);
                    t24 = t23 * 4;
                    *(float*)((char*)t65 + 8) = *(float*)((char*)((char*)a1 + t24) + 8) + *(float*)((char*)((char*)a2 + t24) + 8);
                    t25 = (long long)((int)t1);
                    t26 = t25 * 4;
                    *(float*)((char*)t65 + 0xc) = *(float*)((char*)((char*)a1 + t26) + 0xc) + *(float*)((char*)((char*)a2 + t26) + 0xc);
                    t27 = (long long)((int)t1);
                    t28 = t27 * 4;
                    *(float*)((char*)t65 + 0x10) = *(float*)((char*)((char*)a1 + t28) + 0x10) + *(float*)((char*)((char*)a2 + t28) + 0x10);
                    t29 = (long long)((int)t1);
                    t30 = t29 * 4;
                    *(float*)((char*)((char*)t65 + 0x10) + 4) = *(float*)((char*)((char*)a1 + t30) + 0x14) + *(float*)((char*)((char*)a2 + t30) + 0x14);
                    t31 = (long long)((int)t1);
                    t32 = t31 * 4;
                    *(float*)((char*)((char*)t65 + 0x10) + 8) = *(float*)((char*)((char*)a1 + t32) + 0x18) + *(float*)((char*)((char*)a2 + t32) + 0x18);
                    t33 = (long long)((int)t1);
                    t34 = t33 * 4;
                    *(float*)((char*)((char*)t65 + 0x10) + 0xc) = *(float*)((char*)((char*)a1 + t34) + 0x1c) + *(float*)((char*)((char*)a2 + t34) + 0x1c);
                    t35 = (long long)((int)t1);
                    t36 = t35 * 4;
                    *(float*)((char*)t65 + 0x20) = *(float*)((char*)((char*)a1 + t36) + 0x20) + *(float*)((char*)((char*)a2 + t36) + 0x20);
                    t37 = (long long)((int)t1);
                    t38 = t37 * 4;
                    *(float*)((char*)((char*)t65 + 0x20) + 4) = *(float*)((char*)((char*)a1 + t38) + 0x24) + *(float*)((char*)((char*)a2 + t38) + 0x24);
                    t39 = (long long)((int)t1);
                    t40 = t39 * 4;
                    *(float*)((char*)((char*)t65 + 0x20) + 8) = *(float*)((char*)((char*)a1 + t40) + 0x28) + *(float*)((char*)((char*)a2 + t40) + 0x28);
                    t41 = (long long)((int)t1);
                    t42 = t41 * 4;
                    *(float*)((char*)((char*)t65 + 0x20) + 0xc) = *(float*)((char*)((char*)a1 + t42) + 0x2c) + *(float*)((char*)((char*)a2 + t42) + 0x2c);
                    t43 = (long long)((int)t1);
                    t44 = t43 * 4;
                    *(float*)((char*)t65 + 0x30) = *(float*)((char*)((char*)a1 + t44) + 0x30) + *(float*)((char*)((char*)a2 + t44) + 0x30);
                    t45 = (long long)((int)t1);
                    t46 = t45 * 4;
                    *(float*)((char*)((char*)t65 + 0x30) + 4) = *(float*)((char*)((char*)a1 + t46) + 0x34) + *(float*)((char*)((char*)a2 + t46) + 0x34);
                    t47 = (long long)((int)t1);
                    t48 = t47 * 4;
                    *(float*)((char*)((char*)t65 + 0x30) + 8) = *(float*)((char*)((char*)a1 + t48) + 0x38) + *(float*)((char*)((char*)a2 + t48) + 0x38);
                    t49 = (long long)((int)t1);
                    t50 = t49 * 4;
                    *(float*)((char*)((char*)t65 + 0x30) + 0xc) = *(float*)((char*)((char*)a1 + t50) + 0x3c) + *(float*)((char*)((char*)a2 + t50) + 0x3c);
                    t1 = (int)t1 + 0x10;
                    if (t1 >= (a3 & 0xfffffff0)) break;
                }
                t6 = t1;
                t7 = t1;
                if (((signed char)a3 & 0xe) != 0) {
                    goto L_10a7;
                }
            }
            t8 = t7;
            if ((int)t7 < a3) {
                goto L_10d3;
            }
        } else {
            t8 = 0;
            if ((unsigned long long)((char*)a1 + -4 + (long long)a3 * 4) >= (unsigned long long)(a2)) {
                goto L_10d3;
            } else {
                goto L_1037;
            }
        }
        return;
    }
}


/* fdotv @ 0x1160  size=127 */
float fdotv(float*a1, float*a2, int a3) {
    long long t1;
    float t2;
    long long t3;
    float t4;
    long long t5;
    float t6;
    float t7;
    long long t8;
    long long t9;
    float*t10;
    float*t11;
    long long t12;
    long long t13;
    float*t14;
    float*t15;
    long long t16;
    long long t17;
    long long t18;
    long long t19;

    t5 = 0;
    t6 = 0.0f;
    if (a3 >= 4) {
        t1 = 0;
        t2 = 0.0f;
        while (true) {
            t5 = (int)t1 + 4;
            t8 = (long long)((int)t1);
            t9 = t8 * 4;
            t10 = (float*)((char*)a1 + t9);
            t11 = (float*)((char*)a2 + t9);
            t6 = *t10 * *t11 + t2 + *(float*)((char*)t10 + 4) * *(float*)((char*)t11 + 4) + *(float*)((char*)t10 + 8) * *(float*)((char*)t11 + 8) + *(float*)((char*)t10 + 0xc) * *(float*)((char*)t11 + 0xc);
            t12 = (long long)((int)t1);
            t13 = t12 * 4;
            t14 = (float*)((char*)a1 + t13);
            t15 = (float*)((char*)a2 + t13);
            t2 = *t14 * *t15 + t2 + *(float*)((char*)t14 + 4) * *(float*)((char*)t15 + 4) + *(float*)((char*)t14 + 8) * *(float*)((char*)t15 + 8) + *(float*)((char*)t14 + 0xc) * *(float*)((char*)t15 + 0xc);
            t1 = (int)t1 + 4;
            if (t1 >= (int)(a3 + -3)) break;
        }
    }
    t3 = t5;
    t4 = t6;
    t7 = t6;
    if ((int)t5 >= a3) {
        return t7;
    }
    while (true) {
        t16 = (long long)((int)t3);
        t17 = t16 * 4;
        t7 = t4 + *(float*)((char*)a2 + t17) * *(float*)((char*)a1 + t17);
        t18 = (long long)((int)t3);
        t19 = t18 * 4;
        t4 = t4 + *(float*)((char*)a2 + t19) * *(float*)((char*)a1 + t19);
        t3 = (int)t3 + 1;
        if (t3 >= a3) break;
    }
    return t7;
}


/* fsaxpy @ 0x11e0  size=336 */
void fsaxpy(float*a1, float*a2, float a3, int a4) {
    long long t1;
    long long t2;
    long long t3;
    long long t5;
    long long t16;
    long long t17;
    long long t18;
    long long t19;
    long long t20;
    long long t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    long long t37;
    long long t38;
    long long t39;
    long long t40;
    long long t41;
    long long t42;
    long long t43;
    long long t44;
    long long t45;
    long long t46;
    long long t47;
    long long t48;
    long long t49;
    long long t50;
    long long t51;
    long long t52;
    long long t53;
    long long t54;
    long long t55;
    long long t56;
    long long t57;
    float*t58;
    float*t59;

    if (a4 <= 0) {
        return;
    }
    t5 = 0;
    if ((unsigned int)(a4) < (unsigned int)(0x10)) {
L_1296:;
        t3 = t5;
        if (a4 - (int)t5 >= 4) {
            t2 = t5;
            while (true) {
                t48 = (long long)((int)t2);
                t49 = t48 * 4;
                t59 = (float*)((char*)a1 + (long long)((int)t2) * 4);
                *t59 = a3 * *(float*)((char*)a2 + t49) + *(float*)((char*)a1 + t49);
                t50 = (long long)((int)t2);
                t51 = t50 * 4;
                *(float*)((char*)t59 + 4) = a3 * *(float*)((char*)((char*)a2 + t51) + 4) + *(float*)((char*)((char*)a1 + t51) + 4);
                t52 = (long long)((int)t2);
                t53 = t52 * 4;
                *(float*)((char*)t59 + 8) = a3 * *(float*)((char*)((char*)a2 + t53) + 8) + *(float*)((char*)((char*)a1 + t53) + 8);
                t54 = (long long)((int)t2);
                t55 = t54 * 4;
                *(float*)((char*)t59 + 0xc) = a3 * *(float*)((char*)((char*)a2 + t55) + 0xc) + *(float*)((char*)((char*)a1 + t55) + 0xc);
                t2 = (int)t2 + 4;
                if (t2 >= (int)(a4 + -3)) break;
            }
            t3 = t2;
            if (t2 >= a4) {
                return;
            }
        }
        while (true) {
            t56 = (long long)((int)t3);
            t57 = t56 * 4;
            a1[t3] = a3 * *(float*)((char*)a2 + t57) + *(float*)((char*)a1 + t57);
            t3 = (int)t3 + 1;
            if (t3 >= a4) break;
        }
        return;
    } else {
        if ((unsigned long long)(a1) > (unsigned long long)((char*)a2 + -4 + (long long)a4 * 4)) {
L_121d:;
            t1 = 0;
            while (true) {
                t16 = (long long)((int)t1);
                t17 = t16 * 4;
                t58 = (float*)((char*)a1 + (long long)((int)t1) * 4);
                *t58 = *(float*)((char*)a2 + t17) * a3 + *(float*)((char*)a1 + t17);
                t18 = (long long)((int)t1);
                t19 = t18 * 4;
                *(float*)((char*)t58 + 4) = *(float*)((char*)((char*)a2 + t19) + 4) * a3 + *(float*)((char*)((char*)a1 + t19) + 4);
                t20 = (long long)((int)t1);
                t21 = t20 * 4;
                *(float*)((char*)t58 + 8) = *(float*)((char*)((char*)a2 + t21) + 8) * a3 + *(float*)((char*)((char*)a1 + t21) + 8);
                t22 = (long long)((int)t1);
                t23 = t22 * 4;
                *(float*)((char*)t58 + 0xc) = *(float*)((char*)((char*)a2 + t23) + 0xc) * a3 + *(float*)((char*)((char*)a1 + t23) + 0xc);
                t24 = (long long)((int)t1);
                t25 = t24 * 4;
                *(float*)((char*)t58 + 0x10) = *(float*)((char*)((char*)a2 + t25) + 0x10) * a3 + *(float*)((char*)((char*)a1 + t25) + 0x10);
                t26 = (long long)((int)t1);
                t27 = t26 * 4;
                *(float*)((char*)((char*)t58 + 0x10) + 4) = *(float*)((char*)((char*)a2 + t27) + 0x14) * a3 + *(float*)((char*)((char*)a1 + t27) + 0x14);
                t28 = (long long)((int)t1);
                t29 = t28 * 4;
                *(float*)((char*)((char*)t58 + 0x10) + 8) = *(float*)((char*)((char*)a2 + t29) + 0x18) * a3 + *(float*)((char*)((char*)a1 + t29) + 0x18);
                t30 = (long long)((int)t1);
                t31 = t30 * 4;
                *(float*)((char*)((char*)t58 + 0x10) + 0xc) = *(float*)((char*)((char*)a2 + t31) + 0x1c) * a3 + *(float*)((char*)((char*)a1 + t31) + 0x1c);
                t32 = (long long)((int)t1);
                t33 = t32 * 4;
                *(float*)((char*)t58 + 0x20) = *(float*)((char*)((char*)a2 + t33) + 0x20) * a3 + *(float*)((char*)((char*)a1 + t33) + 0x20);
                t34 = (long long)((int)t1);
                t35 = t34 * 4;
                *(float*)((char*)((char*)t58 + 0x20) + 4) = *(float*)((char*)((char*)a2 + t35) + 0x24) * a3 + *(float*)((char*)((char*)a1 + t35) + 0x24);
                t36 = (long long)((int)t1);
                t37 = t36 * 4;
                *(float*)((char*)((char*)t58 + 0x20) + 8) = *(float*)((char*)((char*)a2 + t37) + 0x28) * a3 + *(float*)((char*)((char*)a1 + t37) + 0x28);
                t38 = (long long)((int)t1);
                t39 = t38 * 4;
                *(float*)((char*)((char*)t58 + 0x20) + 0xc) = *(float*)((char*)((char*)a2 + t39) + 0x2c) * a3 + *(float*)((char*)((char*)a1 + t39) + 0x2c);
                t40 = (long long)((int)t1);
                t41 = t40 * 4;
                *(float*)((char*)t58 + 0x30) = *(float*)((char*)((char*)a2 + t41) + 0x30) * a3 + *(float*)((char*)((char*)a1 + t41) + 0x30);
                t42 = (long long)((int)t1);
                t43 = t42 * 4;
                *(float*)((char*)((char*)t58 + 0x30) + 4) = *(float*)((char*)((char*)a2 + t43) + 0x34) * a3 + *(float*)((char*)((char*)a1 + t43) + 0x34);
                t44 = (long long)((int)t1);
                t45 = t44 * 4;
                *(float*)((char*)((char*)t58 + 0x30) + 8) = *(float*)((char*)((char*)a2 + t45) + 0x38) * a3 + *(float*)((char*)((char*)a1 + t45) + 0x38);
                t46 = (long long)((int)t1);
                t47 = t46 * 4;
                *(float*)((char*)((char*)t58 + 0x30) + 0xc) = *(float*)((char*)((char*)a2 + t47) + 0x3c) * a3 + *(float*)((char*)((char*)a1 + t47) + 0x3c);
                t1 = (int)t1 + 0x10;
                if (t1 >= (a4 & 0xfffffff0)) break;
            }
            t5 = t1;
            if (t1 < a4) {
                goto L_1296;
            }
        } else {
            t5 = 0;
            if ((unsigned long long)((char*)a1 + -4 + (long long)a4 * 4) >= (unsigned long long)(a2)) {
                goto L_1296;
            } else {
                goto L_121d;
            }
        }
        return;
    }
}


/* fscale @ 0x1330  size=181 */
void fscale(float*a1, int a2, float a3) {
    long long t1;
    long long t2;
    long long t3;
    long long t4;
    float*t7;
    float*t8;

    if (a2 <= 0) {
        return;
    }
    t4 = 0;
    if ((unsigned int)(a2) >= (unsigned int)(0x10)) {
        t1 = 0;
        while (true) {
            t7 = (float*)((char*)a1 + (long long)((int)t1) * 4);
            *t7 = *t7 * a3;
            *(float*)((char*)t7 + 4) = *(float*)((char*)t7 + 4) * a3;
            *(float*)((char*)t7 + 8) = *(float*)((char*)t7 + 8) * a3;
            *(float*)((char*)t7 + 0xc) = *(float*)((char*)t7 + 0xc) * a3;
            *(float*)((char*)t7 + 0x10) = *(float*)((char*)t7 + 0x10) * a3;
            *(float*)((char*)((char*)t7 + 0x10) + 4) = *(float*)((char*)t7 + 0x14) * a3;
            *(float*)((char*)((char*)t7 + 0x10) + 8) = *(float*)((char*)t7 + 0x18) * a3;
            *(float*)((char*)((char*)t7 + 0x10) + 0xc) = *(float*)((char*)t7 + 0x1c) * a3;
            *(float*)((char*)t7 + 0x20) = *(float*)((char*)t7 + 0x20) * a3;
            *(float*)((char*)((char*)t7 + 0x20) + 4) = *(float*)((char*)t7 + 0x24) * a3;
            *(float*)((char*)((char*)t7 + 0x20) + 8) = *(float*)((char*)t7 + 0x28) * a3;
            *(float*)((char*)((char*)t7 + 0x20) + 0xc) = *(float*)((char*)t7 + 0x2c) * a3;
            *(float*)((char*)t7 + 0x30) = *(float*)((char*)t7 + 0x30) * a3;
            *(float*)((char*)((char*)t7 + 0x30) + 4) = *(float*)((char*)t7 + 0x34) * a3;
            *(float*)((char*)((char*)t7 + 0x30) + 8) = *(float*)((char*)t7 + 0x38) * a3;
            *(float*)((char*)((char*)t7 + 0x30) + 0xc) = *(float*)((char*)t7 + 0x3c) * a3;
            t1 = (int)t1 + 0x10;
            if (t1 >= (a2 & 0xfffffff0)) break;
        }
        t4 = t1;
        if (t1 >= a2) {
            return;
        }
    }
    t3 = t4;
    if (a2 - (int)t4 >= 4) {
        t2 = t4;
        while (true) {
            t8 = (float*)((char*)a1 + (long long)((int)t2) * 4);
            *t8 = *t8 * a3;
            *(float*)((char*)t8 + 4) = *(float*)((char*)t8 + 4) * a3;
            *(float*)((char*)t8 + 8) = *(float*)((char*)t8 + 8) * a3;
            *(float*)((char*)t8 + 0xc) = *(float*)((char*)t8 + 0xc) * a3;
            t2 = (int)t2 + 4;
            if (t2 >= (int)(a2 + -3)) break;
        }
        t3 = t2;
        if (t2 >= a2) {
            return;
        }
    }
    while (true) {
        a1[t3] = a3 * a1[t3];
        t3 = (int)t3 + 1;
        if (t3 >= a2) break;
    }
    return;
}


/* fsumv @ 0x13f0  size=73 */
float fsumv(float*a1, int a2) {
    long long t1;
    float t2;
    long long t3;
    float t4;
    long long t5;
    float t6;
    float t7;
    long long t8;
    long long t9;
    float*t10;
    long long t11;
    long long t12;
    float*t13;
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
            t10 = (float*)((char*)a1 + t9);
            t6 = t2 + *t10 + *(float*)((char*)t10 + 4) + *(float*)((char*)t10 + 8) + *(float*)((char*)t10 + 0xc);
            t11 = (long long)((int)t1);
            t12 = t11 * 4;
            t13 = (float*)((char*)a1 + t12);
            t2 = t2 + *t13 + *(float*)((char*)t13 + 4) + *(float*)((char*)t13 + 8) + *(float*)((char*)t13 + 0xc);
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


/* iadd @ 0x1440  size=275 */
void iadd(int*a1, int*a2, int a3) {
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
    long long t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    long long t37;
    long long t38;
    long long t39;
    long long t40;
    long long t41;
    long long t42;
    long long t43;
    int*t44;
    int*t45;

    if (a3 <= 0) {
        return;
    }
    t3 = 0;
    if ((unsigned int)(a3) < (unsigned int)(2)) {
L_1540:;
        while (true) {
            t42 = (long long)((int)t3);
            t43 = t42 * 4;
            a1[t3] = *(int*)((char*)a1 + t43) + *(int*)((char*)a2 + t43);
            t3 = (int)t3 + 1;
            if (t3 >= a3) break;
        }
        return;
    } else {
        if ((unsigned long long)(a1) > (unsigned long long)((char*)a2 + -4 + (long long)a3 * 4)) {
L_147b:;
            t4 = 0;
            if ((unsigned int)(a3) < (unsigned int)(0x10)) {
L_1501:;
                t2 = t4;
                while (true) {
                    t38 = (long long)((int)t2);
                    t39 = t38 * 4;
                    t45 = (int*)((char*)a1 + (long long)((int)t2) * 4);
                    *t45 = *(int*)((char*)a1 + t39) + *(int*)((char*)a2 + t39);
                    t40 = (long long)((int)t2);
                    t41 = t40 * 4;
                    *(int*)((char*)t45 + 4) = *(int*)((char*)((char*)a1 + t41) + 4) + *(int*)((char*)((char*)a2 + t41) + 4);
                    t5 = (int)t2 + 2;
                    t2 = (int)t2 + 2;
                    if (t2 >= (a3 & 0xfffffffe)) break;
                }
            } else {
                t1 = 0;
                while (true) {
                    t6 = (long long)((int)t1);
                    t7 = t6 * 4;
                    t44 = (int*)((char*)a1 + (long long)((int)t1) * 4);
                    *t44 = *(int*)((char*)a1 + t7) + *(int*)((char*)a2 + t7);
                    t8 = (long long)((int)t1);
                    t9 = t8 * 4;
                    *(int*)((char*)t44 + 4) = *(int*)((char*)((char*)a1 + t9) + 4) + *(int*)((char*)((char*)a2 + t9) + 4);
                    t10 = (long long)((int)t1);
                    t11 = t10 * 4;
                    *(int*)((char*)t44 + 8) = *(int*)((char*)((char*)a1 + t11) + 8) + *(int*)((char*)((char*)a2 + t11) + 8);
                    t12 = (long long)((int)t1);
                    t13 = t12 * 4;
                    *(int*)((char*)t44 + 0xc) = *(int*)((char*)((char*)a1 + t13) + 0xc) + *(int*)((char*)((char*)a2 + t13) + 0xc);
                    t14 = (long long)((int)t1);
                    t15 = t14 * 4;
                    *(int*)((char*)t44 + 0x10) = *(int*)((char*)((char*)a1 + t15) + 0x10) + *(int*)((char*)((char*)a2 + t15) + 0x10);
                    t16 = (long long)((int)t1);
                    t17 = t16 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 4) = *(int*)((char*)((char*)a1 + t17) + 0x14) + *(int*)((char*)((char*)a2 + t17) + 0x14);
                    t18 = (long long)((int)t1);
                    t19 = t18 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 8) = *(int*)((char*)((char*)a1 + t19) + 0x18) + *(int*)((char*)((char*)a2 + t19) + 0x18);
                    t20 = (long long)((int)t1);
                    t21 = t20 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 0xc) = *(int*)((char*)((char*)a1 + t21) + 0x1c) + *(int*)((char*)((char*)a2 + t21) + 0x1c);
                    t22 = (long long)((int)t1);
                    t23 = t22 * 4;
                    *(int*)((char*)t44 + 0x20) = *(int*)((char*)((char*)a1 + t23) + 0x20) + *(int*)((char*)((char*)a2 + t23) + 0x20);
                    t24 = (long long)((int)t1);
                    t25 = t24 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 4) = *(int*)((char*)((char*)a1 + t25) + 0x24) + *(int*)((char*)((char*)a2 + t25) + 0x24);
                    t26 = (long long)((int)t1);
                    t27 = t26 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 8) = *(int*)((char*)((char*)a1 + t27) + 0x28) + *(int*)((char*)((char*)a2 + t27) + 0x28);
                    t28 = (long long)((int)t1);
                    t29 = t28 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 0xc) = *(int*)((char*)((char*)a1 + t29) + 0x2c) + *(int*)((char*)((char*)a2 + t29) + 0x2c);
                    t30 = (long long)((int)t1);
                    t31 = t30 * 4;
                    *(int*)((char*)t44 + 0x30) = *(int*)((char*)((char*)a1 + t31) + 0x30) + *(int*)((char*)((char*)a2 + t31) + 0x30);
                    t32 = (long long)((int)t1);
                    t33 = t32 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 4) = *(int*)((char*)((char*)a1 + t33) + 0x34) + *(int*)((char*)((char*)a2 + t33) + 0x34);
                    t34 = (long long)((int)t1);
                    t35 = t34 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 8) = *(int*)((char*)((char*)a1 + t35) + 0x38) + *(int*)((char*)((char*)a2 + t35) + 0x38);
                    t36 = (long long)((int)t1);
                    t37 = t36 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 0xc) = *(int*)((char*)((char*)a1 + t37) + 0x3c) + *(int*)((char*)((char*)a2 + t37) + 0x3c);
                    t1 = (int)t1 + 0x10;
                    if (t1 >= (a3 & 0xfffffff0)) break;
                }
                t4 = t1;
                t5 = t1;
                if (((signed char)a3 & 0xe) != 0) {
                    goto L_1501;
                }
            }
            if ((int)t5 < a3) {
                t3 = t5;
                goto L_1540;
            }
        } else {
            t3 = 0;
            if ((unsigned long long)((char*)a1 + ((long long)a3 - 1) * 4) >= (unsigned long long)(a2)) {
                goto L_1540;
            } else {
                goto L_147b;
            }
        }
        return;
    }
}


/* iaxpy @ 0x1560  size=263 */
void iaxpy(int*a1, int*a2, int a3, int a4) {
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
    long long t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    int*t37;

    if (a4 <= 0) {
        return;
    }
    t2 = 0;
    if ((unsigned int)(a4) < (unsigned int)(0x10)) {
L_1650:;
        while (true) {
            t35 = (long long)((int)t2);
            t36 = t35 * 4;
            a1[t2] = *(int*)((char*)a1 + t36) + a3 * *(int*)((char*)a2 + t36);
            t2 = (int)t2 + 1;
            if (t2 >= a4) break;
        }
        return;
    } else {
        t2 = 0;
        if (dword_19000 < 2) {
            goto L_1650;
        } else {
            if ((unsigned long long)(a1) > (unsigned long long)((char*)a2 + ((long long)a4 + -1) * 4)) {
L_15b3:;
                t1 = 0;
                while (true) {
                    t3 = (long long)((int)t1);
                    t4 = t3 * 4;
                    t37 = (int*)((char*)a1 + (long long)((int)t1) * 4);
                    *t37 = *(int*)((char*)a2 + t4) * a3 + *(int*)((char*)a1 + t4);
                    t5 = (long long)((int)t1);
                    t6 = t5 * 4;
                    *(int*)((char*)t37 + 4) = *(int*)((char*)((char*)a2 + t6) + 4) * a3 + *(int*)((char*)((char*)a1 + t6) + 4);
                    t7 = (long long)((int)t1);
                    t8 = t7 * 4;
                    *(int*)((char*)t37 + 8) = *(int*)((char*)((char*)a2 + t8) + 8) * a3 + *(int*)((char*)((char*)a1 + t8) + 8);
                    t9 = (long long)((int)t1);
                    t10 = t9 * 4;
                    *(int*)((char*)t37 + 0xc) = *(int*)((char*)((char*)a2 + t10) + 0xc) * a3 + *(int*)((char*)((char*)a1 + t10) + 0xc);
                    t11 = (long long)((int)t1);
                    t12 = t11 * 4;
                    *(int*)((char*)t37 + 0x10) = *(int*)((char*)((char*)a2 + t12) + 0x10) * a3 + *(int*)((char*)((char*)a1 + t12) + 0x10);
                    t13 = (long long)((int)t1);
                    t14 = t13 * 4;
                    *(int*)((char*)((char*)t37 + 0x10) + 4) = *(int*)((char*)((char*)a2 + t14) + 0x14) * a3 + *(int*)((char*)((char*)a1 + t14) + 0x14);
                    t15 = (long long)((int)t1);
                    t16 = t15 * 4;
                    *(int*)((char*)((char*)t37 + 0x10) + 8) = *(int*)((char*)((char*)a2 + t16) + 0x18) * a3 + *(int*)((char*)((char*)a1 + t16) + 0x18);
                    t17 = (long long)((int)t1);
                    t18 = t17 * 4;
                    *(int*)((char*)((char*)t37 + 0x10) + 0xc) = *(int*)((char*)((char*)a2 + t18) + 0x1c) * a3 + *(int*)((char*)((char*)a1 + t18) + 0x1c);
                    t19 = (long long)((int)t1);
                    t20 = t19 * 4;
                    *(int*)((char*)t37 + 0x20) = *(int*)((char*)((char*)a2 + t20) + 0x20) * a3 + *(int*)((char*)((char*)a1 + t20) + 0x20);
                    t21 = (long long)((int)t1);
                    t22 = t21 * 4;
                    *(int*)((char*)((char*)t37 + 0x20) + 4) = *(int*)((char*)((char*)a2 + t22) + 0x24) * a3 + *(int*)((char*)((char*)a1 + t22) + 0x24);
                    t23 = (long long)((int)t1);
                    t24 = t23 * 4;
                    *(int*)((char*)((char*)t37 + 0x20) + 8) = *(int*)((char*)((char*)a2 + t24) + 0x28) * a3 + *(int*)((char*)((char*)a1 + t24) + 0x28);
                    t25 = (long long)((int)t1);
                    t26 = t25 * 4;
                    *(int*)((char*)((char*)t37 + 0x20) + 0xc) = *(int*)((char*)((char*)a2 + t26) + 0x2c) * a3 + *(int*)((char*)((char*)a1 + t26) + 0x2c);
                    t27 = (long long)((int)t1);
                    t28 = t27 * 4;
                    *(int*)((char*)t37 + 0x30) = *(int*)((char*)((char*)a2 + t28) + 0x30) * a3 + *(int*)((char*)((char*)a1 + t28) + 0x30);
                    t29 = (long long)((int)t1);
                    t30 = t29 * 4;
                    *(int*)((char*)((char*)t37 + 0x30) + 4) = *(int*)((char*)((char*)a2 + t30) + 0x34) * a3 + *(int*)((char*)((char*)a1 + t30) + 0x34);
                    t31 = (long long)((int)t1);
                    t32 = t31 * 4;
                    *(int*)((char*)((char*)t37 + 0x30) + 8) = *(int*)((char*)((char*)a2 + t32) + 0x38) * a3 + *(int*)((char*)((char*)a1 + t32) + 0x38);
                    t33 = (long long)((int)t1);
                    t34 = t33 * 4;
                    *(int*)((char*)((char*)t37 + 0x30) + 0xc) = *(int*)((char*)((char*)a2 + t34) + 0x3c) * a3 + *(int*)((char*)((char*)a1 + t34) + 0x3c);
                    t1 = (int)t1 + 0x10;
                    if (t1 >= (a4 & 0xfffffff0)) break;
                }
                if (t1 < a4) {
                    t2 = t1;
                    goto L_1650;
                }
            } else {
                t2 = 0;
                if ((unsigned long long)((char*)a1 + ((long long)a4 + -1) * 4) >= (unsigned long long)(a2)) {
                    goto L_1650;
                } else {
                    goto L_15b3;
                }
            }
        }
        return;
    }
}


/* idot @ 0x1670  size=273 */
int idot(int*a1, int*a2, int a3) {
    long long t1;
    int t2;
    int t3;
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
    int t16;
    int t17;
    int t18;
    int t19;
    int t20;
    int t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    long long t37;
    long long t38;
    long long t39;
    long long t40;
    long long t41;
    long long t42;
    long long t43;
    int t44;

    t15 = 0;
    if (a3 <= 0) {
        return (int)t15;
    }
    t7 = 0;
    t8 = 0;
    if ((unsigned int)(a3) < (unsigned int)(8)) {
L_170c:;
        t9 = t7;
        t10 = 0;
        t11 = 0;
        if (a3 - (int)t7 < 2) {
            t42 = (long long)((int)t9);
            t43 = t42 * 4;
            t12 = (int)t8 + *(int*)((char*)a1 + t43) * *(int*)((char*)a2 + t43);
            t13 = t10;
            t14 = t11;
            return (int)(t14 + t13) + (int)t12;
        }
        t4 = t7;
        t5 = 0;
        t6 = 0;
        while (true) {
            t38 = (long long)((int)t4);
            t39 = t38 * 4;
            t5 = (int)t5 + *(int*)((char*)a1 + t39) * *(int*)((char*)a2 + t39);
            t40 = (long long)((int)t4);
            t41 = t40 * 4;
            t6 = (int)t6 + *(int*)((char*)((char*)a2 + t41) + 4) * *(int*)((char*)((char*)a1 + t41) + 4);
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
        t42 = (long long)((int)t9);
        t43 = t42 * 4;
        t12 = (int)t8 + *(int*)((char*)a1 + t43) * *(int*)((char*)a2 + t43);
        t13 = t10;
        t14 = t11;
        return (int)(t14 + t13) + (int)t12;
    }
    t7 = 0;
    t8 = 0;
    if (dword_19000 < 2) goto L_170c;
    t1 = 0;
    t2 = 0;
    t3 = 0;
    t16 = 0;
    t17 = 0;
    t18 = 0;
    t19 = 0;
    t20 = 0;
    t21 = 0;
    while (true) {
        t22 = (long long)((int)t1);
        t23 = t22 * 4;
        t2 = t2 + *(int*)((char*)((char*)a1 + t23) + 0x10) * *(int*)((char*)((char*)a2 + t23) + 0x10);
        t24 = (long long)((int)t1);
        t25 = t24 * 4;
        t3 = t3 + *(int*)((char*)a1 + t25) * *(int*)((char*)a2 + t25);
        t26 = (long long)((int)t1);
        t27 = t26 * 4;
        t16 = t16 + *(int*)((char*)((char*)a1 + t27) + 0x14) * *(int*)((char*)((char*)a2 + t27) + 0x14);
        t28 = (long long)((int)t1);
        t29 = t28 * 4;
        t17 = t17 + *(int*)((char*)((char*)a1 + t29) + 0x18) * *(int*)((char*)((char*)a2 + t29) + 0x18);
        t30 = (long long)((int)t1);
        t31 = t30 * 4;
        t18 = t18 + *(int*)((char*)((char*)a1 + t31) + 0x1c) * *(int*)((char*)((char*)a2 + t31) + 0x1c);
        t32 = (long long)((int)t1);
        t33 = t32 * 4;
        t19 = t19 + *(int*)((char*)((char*)a1 + t33) + 4) * *(int*)((char*)((char*)a2 + t33) + 4);
        t34 = (long long)((int)t1);
        t35 = t34 * 4;
        t20 = t20 + *(int*)((char*)((char*)a1 + t35) + 8) * *(int*)((char*)((char*)a2 + t35) + 8);
        t36 = (long long)((int)t1);
        t37 = t36 * 4;
        t21 = t21 + *(int*)((char*)((char*)a1 + t37) + 0xc) * *(int*)((char*)((char*)a2 + t37) + 0xc);
        t1 = (int)t1 + 8;
        if (t1 >= (a3 & 0xfffffff8)) break;
    }
    t7 = t1;
    t44 = t2 + t3 + (t17 + t20) + (t16 + t19 + (t18 + t21));
    t8 = t44;
    t15 = t44;
    if (t1 >= a3) {
        return (int)t15;
    }
    goto L_170c;
}


/* imax @ 0x1790  size=188 */
int imax(int*a1, int a2) {
    long long t1;
    long long t2;
    long long t4;
    long long t5;
    long long t6;
    long long t8;
    long long t10;
    long long t11;
    int*t12;
    int t9;

    t8 = *a1;
    if (a2 <= 1) {
        return (int)t8;
    }
    t4 = 1;
    t5 = *a1;
    if ((unsigned int)((int)(a2 + -1)) < (unsigned int)(8)) {
L_1830:;
        while (true) {
            t10 = (long long)((int)t4);
            t11 = t10 * 4;
            t12 = (int*)((char*)a1 + t11);
            t9 = *t12 <= (int)t5 ? (int)t5 : *t12;
            t4 = (int)t4 + 1;
            t5 = t9;
            t8 = t9;
            if (t4 >= a2) break;
        }
        return (int)t8;
    } else {
        t4 = 1;
        t5 = *a1;
        if (dword_19000 < 2) {
            goto L_1830;
        } else {
            t6 = (int)(a2 + -1) & 0x80000007;
            if (t6 < 0) {
                t6 = ((((int)(a2 + -1) & 0x80000007) - 1) | 0xfffffff8) + 1;
            }
            t1 = 1;
            t2 = *a1;
            while (true) {
                t1 = (int)t1 + 8;
                if (t1 >= a2 - (int)t6) break;
            }
            t8 = t2;
            if (t1 < a2) {
                t4 = t1;
                t5 = t2;
                goto L_1830;
            }
        }
        return (int)t8;
    }
}


/* iscale @ 0x1850  size=167 */
void iscale(int*a1, int a2, int a3) {
    long long t1;
    long long t2;
    int*t5;

    if (a2 <= 0) {
        return;
    }
    t2 = 0;
    if ((unsigned int)(a2) < (unsigned int)(0x10)) {
L_18e0:;
        while (true) {
            a1[t2] = a3 * a1[t2];
            t2 = (int)t2 + 1;
            if (t2 >= a2) break;
        }
        return;
    } else {
        t2 = 0;
        if (dword_19000 < 2) {
            goto L_18e0;
        } else {
            t1 = 0;
            while (true) {
                t5 = (int*)((char*)a1 + (long long)((int)t1) * 4);
                *t5 = *t5 * a3;
                *(int*)((char*)t5 + 4) = *(int*)((char*)t5 + 4) * a3;
                *(int*)((char*)t5 + 8) = *(int*)((char*)t5 + 8) * a3;
                *(int*)((char*)t5 + 0xc) = *(int*)((char*)t5 + 0xc) * a3;
                *(int*)((char*)t5 + 0x10) = *(int*)((char*)t5 + 0x10) * a3;
                *(int*)((char*)((char*)t5 + 0x10) + 4) = *(int*)((char*)t5 + 0x14) * a3;
                *(int*)((char*)((char*)t5 + 0x10) + 8) = *(int*)((char*)t5 + 0x18) * a3;
                *(int*)((char*)((char*)t5 + 0x10) + 0xc) = *(int*)((char*)t5 + 0x1c) * a3;
                *(int*)((char*)t5 + 0x20) = *(int*)((char*)t5 + 0x20) * a3;
                *(int*)((char*)((char*)t5 + 0x20) + 4) = *(int*)((char*)t5 + 0x24) * a3;
                *(int*)((char*)((char*)t5 + 0x20) + 8) = *(int*)((char*)t5 + 0x28) * a3;
                *(int*)((char*)((char*)t5 + 0x20) + 0xc) = *(int*)((char*)t5 + 0x2c) * a3;
                *(int*)((char*)t5 + 0x30) = *(int*)((char*)t5 + 0x30) * a3;
                *(int*)((char*)((char*)t5 + 0x30) + 4) = *(int*)((char*)t5 + 0x34) * a3;
                *(int*)((char*)((char*)t5 + 0x30) + 8) = *(int*)((char*)t5 + 0x38) * a3;
                *(int*)((char*)((char*)t5 + 0x30) + 0xc) = *(int*)((char*)t5 + 0x3c) * a3;
                t1 = (int)t1 + 0x10;
                if (t1 >= (a2 & 0xfffffff0)) break;
            }
            if (t1 < a2) {
                t2 = t1;
                goto L_18e0;
            }
        }
        return;
    }
}


/* isub @ 0x1900  size=275 */
void isub(int*a1, int*a2, int a3) {
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
    long long t21;
    long long t22;
    long long t23;
    long long t24;
    long long t25;
    long long t26;
    long long t27;
    long long t28;
    long long t29;
    long long t30;
    long long t31;
    long long t32;
    long long t33;
    long long t34;
    long long t35;
    long long t36;
    long long t37;
    long long t38;
    long long t39;
    long long t40;
    long long t41;
    long long t42;
    long long t43;
    int*t44;
    int*t45;

    if (a3 <= 0) {
        return;
    }
    t3 = 0;
    if ((unsigned int)(a3) < (unsigned int)(2)) {
L_1a00:;
        while (true) {
            t42 = (long long)((int)t3);
            t43 = t42 * 4;
            a1[t3] = *(int*)((char*)a1 + t43) - *(int*)((char*)a2 + t43);
            t3 = (int)t3 + 1;
            if (t3 >= a3) break;
        }
        return;
    } else {
        if ((unsigned long long)(a1) > (unsigned long long)((char*)a2 + -4 + (long long)a3 * 4)) {
L_193b:;
            t4 = 0;
            if ((unsigned int)(a3) < (unsigned int)(0x10)) {
L_19c1:;
                t2 = t4;
                while (true) {
                    t38 = (long long)((int)t2);
                    t39 = t38 * 4;
                    t45 = (int*)((char*)a1 + (long long)((int)t2) * 4);
                    *t45 = *(int*)((char*)a1 + t39) - *(int*)((char*)a2 + t39);
                    t40 = (long long)((int)t2);
                    t41 = t40 * 4;
                    *(int*)((char*)t45 + 4) = *(int*)((char*)((char*)a1 + t41) + 4) - *(int*)((char*)((char*)a2 + t41) + 4);
                    t5 = (int)t2 + 2;
                    t2 = (int)t2 + 2;
                    if (t2 >= (a3 & 0xfffffffe)) break;
                }
            } else {
                t1 = 0;
                while (true) {
                    t6 = (long long)((int)t1);
                    t7 = t6 * 4;
                    t44 = (int*)((char*)a1 + (long long)((int)t1) * 4);
                    *t44 = *(int*)((char*)a1 + t7) - *(int*)((char*)a2 + t7);
                    t8 = (long long)((int)t1);
                    t9 = t8 * 4;
                    *(int*)((char*)t44 + 4) = *(int*)((char*)((char*)a1 + t9) + 4) - *(int*)((char*)((char*)a2 + t9) + 4);
                    t10 = (long long)((int)t1);
                    t11 = t10 * 4;
                    *(int*)((char*)t44 + 8) = *(int*)((char*)((char*)a1 + t11) + 8) - *(int*)((char*)((char*)a2 + t11) + 8);
                    t12 = (long long)((int)t1);
                    t13 = t12 * 4;
                    *(int*)((char*)t44 + 0xc) = *(int*)((char*)((char*)a1 + t13) + 0xc) - *(int*)((char*)((char*)a2 + t13) + 0xc);
                    t14 = (long long)((int)t1);
                    t15 = t14 * 4;
                    *(int*)((char*)t44 + 0x10) = *(int*)((char*)((char*)a1 + t15) + 0x10) - *(int*)((char*)((char*)a2 + t15) + 0x10);
                    t16 = (long long)((int)t1);
                    t17 = t16 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 4) = *(int*)((char*)((char*)a1 + t17) + 0x14) - *(int*)((char*)((char*)a2 + t17) + 0x14);
                    t18 = (long long)((int)t1);
                    t19 = t18 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 8) = *(int*)((char*)((char*)a1 + t19) + 0x18) - *(int*)((char*)((char*)a2 + t19) + 0x18);
                    t20 = (long long)((int)t1);
                    t21 = t20 * 4;
                    *(int*)((char*)((char*)t44 + 0x10) + 0xc) = *(int*)((char*)((char*)a1 + t21) + 0x1c) - *(int*)((char*)((char*)a2 + t21) + 0x1c);
                    t22 = (long long)((int)t1);
                    t23 = t22 * 4;
                    *(int*)((char*)t44 + 0x20) = *(int*)((char*)((char*)a1 + t23) + 0x20) - *(int*)((char*)((char*)a2 + t23) + 0x20);
                    t24 = (long long)((int)t1);
                    t25 = t24 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 4) = *(int*)((char*)((char*)a1 + t25) + 0x24) - *(int*)((char*)((char*)a2 + t25) + 0x24);
                    t26 = (long long)((int)t1);
                    t27 = t26 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 8) = *(int*)((char*)((char*)a1 + t27) + 0x28) - *(int*)((char*)((char*)a2 + t27) + 0x28);
                    t28 = (long long)((int)t1);
                    t29 = t28 * 4;
                    *(int*)((char*)((char*)t44 + 0x20) + 0xc) = *(int*)((char*)((char*)a1 + t29) + 0x2c) - *(int*)((char*)((char*)a2 + t29) + 0x2c);
                    t30 = (long long)((int)t1);
                    t31 = t30 * 4;
                    *(int*)((char*)t44 + 0x30) = *(int*)((char*)((char*)a1 + t31) + 0x30) - *(int*)((char*)((char*)a2 + t31) + 0x30);
                    t32 = (long long)((int)t1);
                    t33 = t32 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 4) = *(int*)((char*)((char*)a1 + t33) + 0x34) - *(int*)((char*)((char*)a2 + t33) + 0x34);
                    t34 = (long long)((int)t1);
                    t35 = t34 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 8) = *(int*)((char*)((char*)a1 + t35) + 0x38) - *(int*)((char*)((char*)a2 + t35) + 0x38);
                    t36 = (long long)((int)t1);
                    t37 = t36 * 4;
                    *(int*)((char*)((char*)t44 + 0x30) + 0xc) = *(int*)((char*)((char*)a1 + t37) + 0x3c) - *(int*)((char*)((char*)a2 + t37) + 0x3c);
                    t1 = (int)t1 + 0x10;
                    if (t1 >= (a3 & 0xfffffff0)) break;
                }
                t4 = t1;
                t5 = t1;
                if (((signed char)a3 & 0xe) != 0) {
                    goto L_19c1;
                }
            }
            if ((int)t5 < a3) {
                t3 = t5;
                goto L_1a00;
            }
        } else {
            t3 = 0;
            if ((unsigned long long)((char*)a1 + ((long long)a3 - 1) * 4) >= (unsigned long long)(a2)) {
                goto L_1a00;
            } else {
                goto L_193b;
            }
        }
        return;
    }
}


/* isum @ 0x1a20  size=199 */
int isum(int*a1, int a2) {
    long long t1;
    int t2;
    int t3;
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
    int t16;
    int t17;
    int t18;
    int t19;
    int t20;
    int t21;
    int*t22;
    int t23;
    int*t24;

    t15 = 0;
    if (a2 <= 0) {
        return (int)t15;
    }
    t7 = 0;
    t8 = 0;
    if ((unsigned int)(a2) >= (unsigned int)(8)) {
        t1 = 0;
        t2 = 0;
        t3 = 0;
        t16 = 0;
        t17 = 0;
        t18 = 0;
        t19 = 0;
        t20 = 0;
        t21 = 0;
        while (true) {
            t22 = (int*)((char*)a1 + (long long)((int)t1) * 4);
            t2 = t2 + *(int*)((char*)t22 + 0x10);
            t3 = t3 + *t22;
            t16 = t16 + *(int*)((char*)t22 + 0x14);
            t17 = t17 + *(int*)((char*)t22 + 0x18);
            t18 = t18 + *(int*)((char*)t22 + 0x1c);
            t19 = t19 + *(int*)((char*)t22 + 4);
            t20 = t20 + *(int*)((char*)t22 + 8);
            t21 = t21 + *(int*)((char*)t22 + 0xc);
            t1 = (int)t1 + 8;
            if (t1 >= (a2 & 0xfffffff8)) break;
        }
        t7 = t1;
        t23 = t2 + t3 + (t17 + t20) + (t16 + t19 + (t18 + t21));
        t8 = t23;
        t15 = t23;
        if (t1 >= a2) {
            return (int)t15;
        }
    }
    t9 = t7;
    t10 = 0;
    t11 = 0;
    if (a2 - (int)t7 < 2) {
        t12 = t10;
        t13 = t11;
        t14 = (int)t8 + a1[t9];
        return (int)(t13 + t12) + (int)t14;
    }
    t4 = t7;
    t5 = 0;
    t6 = 0;
    while (true) {
        t24 = (int*)((char*)a1 + (long long)((int)t4) * 4);
        t5 = (int)t5 + *t24;
        t6 = (int)t6 + *(int*)((char*)t24 + 4);
        t4 = (int)t4 + 2;
        if (t4 >= (int)(a2 + -1)) break;
    }
    t9 = t4;
    t10 = t5;
    t11 = t6;
    t12 = t5;
    t13 = t6;
    t14 = t8;
    if (t4 >= a2) {
        return (int)(t13 + t12) + (int)t14;
    }
    t12 = t10;
    t13 = t11;
    t14 = (int)t8 + a1[t9];
    return (int)(t13 + t12) + (int)t14;
}


/* isum64 @ 0x1af0  size=188 */
long long isum64(int*a1, int a2) {
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
    int*t18;
    long long t19;
    int*t20;

    t15 = 0;
    if (a2 <= 0) {
        return t15;
    }
    t7 = 0;
    t8 = 0;
    if ((unsigned int)(a2) < (unsigned int)(4)) {
L_1b5b:;
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
            t20 = (int*)((char*)a1 + (long long)((int)t4) * 4);
            t5 = t5 + (long long)*t20;
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
    if (dword_19000 < 2) goto L_1b5b;
    t1 = 0;
    t2 = 0;
    t3 = 0;
    t16 = 0;
    t17 = 0;
    while (true) {
        t18 = (int*)((char*)a1 + (long long)((int)t1) * 4);
        t2 = t2 + (long long)*(int*)((char*)t18 + 8);
        t3 = t3 + (long long)*t18;
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
    goto L_1b5b;
}


