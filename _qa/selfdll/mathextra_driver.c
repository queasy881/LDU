/* Driver for mathextra: exercise every export over a range of inputs and print
 * results deterministically so ref (source) and dec (decompiled) outputs diff. */
#include <stdio.h>
#include <stdint.h>

#define API
float  vec_len2(float, float);
float  vec_len3(float, float, float);
float  fdist(float, float, float, float);
double dhypot(double, double);
float  fnorm_x(float, float);
int    d_signbit(double);
int    d_isneg(double);
double d_fabs(double);
double d_copysign(double, double);
int    d_expo(double);

int main(void) {
    static const double D[] = { 0.0, -0.0, 1.0, -1.0, 2.5, -2.5, 100.0, -100.0,
                                0.125, -0.125, 3.14159, -3.14159, 1e9, -1e9, 1e-9, -1e-9 };
    static const float  F[] = { 0.0f, 1.0f, -1.0f, 3.0f, 4.0f, -4.0f, 0.5f, 12.0f,
                                7.0f, -7.0f, 100.0f, 0.25f, 9.0f, 16.0f, 2.0f, -2.0f };
    int nd = (int)(sizeof(D)/sizeof(D[0])), nf = (int)(sizeof(F)/sizeof(F[0]));

    for (int i = 0; i < nf; i++)
        for (int j = 0; j < nf; j++) {
            printf("len2 %.6f\n", vec_len2(F[i], F[j]));
            printf("dist %.6f\n", fdist(F[i], F[j], F[j], F[i]));
            printf("norm %.6f\n", fnorm_x(F[i], F[j]));
        }
    for (int i = 0; i < nf; i++)
        for (int j = 0; j < nf; j++)
            for (int k = 0; k < nf; k += 3)
                printf("len3 %.6f\n", vec_len3(F[i], F[j], F[k]));

    for (int i = 0; i < nd; i++) {
        printf("sb %d isn %d expo %d\n", d_signbit(D[i]), d_isneg(D[i]), d_expo(D[i]));
        printf("fabs %.9f\n", d_fabs(D[i]));
        for (int j = 0; j < nd; j++) {
            printf("hyp %.9f\n", dhypot(D[i], D[j]));
            printf("cs %.9f\n", d_copysign(D[i], D[j]));
        }
    }
    return 0;
}
