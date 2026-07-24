/* FEATURE FIXTURE (32-bit, /arch:IA32) — x87. Until milestone 30 the whole x87 unit was
 * unmodeled and EVERY /arch:IA32 float function decompiled to an empty `void f(void){}`.
 * These assert the math survives. Build: cl /nologo /O2 /LD /TC /arch:IA32 feat_x87.c
 */
__declspec(dllexport) double x87_add(double a, double b) { return a + b; }
__declspec(dllexport) double x87_muladd(double a, double b, double c) { return a * b + c; }
/* the CC::P/NP inversion bug lived here: a compare whose sense flipped every x87 test */
__declspec(dllexport) int x87_cmp(double a, double b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}
__declspec(dllexport) float x87_f(float a, float b) { return a / b; }
