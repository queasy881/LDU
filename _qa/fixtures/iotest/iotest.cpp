// iotest.cpp — ground truth for I/O recovery in the decompiler.
//
// Every function here is exported and does exactly one recognisable thing, so
// the decompiled output can be checked against a known answer:
//   * printf / fprintf / sprintf / snprintf  (varargs, format string)
//   * puts / putchar
//   * scanf / sscanf  (input, out-params)
//   * std::cin >> / std::cout <<  (C++ iostreams -> operator>> / operator<<)
//   * std::getline, std::string
//
// Build:  cl /O2 /EHsc /LD iotest.cpp /Fe:iotest.dll
//    or:  cl /Od /EHsc /LD iotest.cpp /Fe:iotest_od.dll   (both are worth checking)
#include <cstdio>
#include <iostream>
#include <string>

#define API extern "C" __declspec(dllexport)

/* ---- C output ---------------------------------------------------------- */

API void io_printf_simple(int v) {
    printf("value = %d\n", v);
}

API void io_printf_multi(int a, const char* s, double d) {
    printf("a=%d s=%s d=%f\n", a, s, d);
}

API int io_sprintf(char* out, int v) {
    return sprintf(out, "n:%d", v);
}

API int io_snprintf(char* out, unsigned long cap, const char* name) {
    return snprintf(out, cap, "hello %s", name);
}

API void io_fprintf_err(int code) {
    fprintf(stderr, "error %d\n", code);
}

API void io_puts(void) {
    puts("plain line");
}

API void io_putchar(int c) {
    putchar(c);
}

/* ---- C input ------------------------------------------------------------ */

API int io_scanf_one(void) {
    int a = 0;
    scanf("%d", &a);
    return a;
}

API int io_scanf_two(void) {
    int a = 0, b = 0;
    scanf("%d %d", &a, &b);
    return a + b;
}

API int io_sscanf(const char* src) {
    int a = 0, b = 0;
    sscanf(src, "%d,%d", &a, &b);
    return a * b;
}

/* ---- C++ iostreams ------------------------------------------------------ */

API int io_cin_int(void) {
    int a = 0;
    std::cin >> a;                    // operator>>(istream&, int&)
    return a;
}

API int io_cin_two(void) {
    int a = 0, b = 0;
    std::cin >> a >> b;               // chained operator>>
    return a + b;
}

API void io_cout_int(int v) {
    std::cout << v << std::endl;      // operator<<(ostream&, int) then endl
}

API void io_cout_str(void) {
    std::cout << "literal" << '\n';
}

API int io_cin_string(void) {
    std::string s;
    std::cin >> s;                    // operator>>(istream&, string&)
    return (int)s.size();
}

API int io_getline(void) {
    std::string line;
    std::getline(std::cin, line);
    return (int)line.size();
}

API double io_cin_double(void) {
    double d = 0;
    std::cin >> d;
    return d;
}

/* keep the CRT/iostream init referenced so the DLL links standalone */
API int io_roundtrip(int v) {
    char buf[64];
    sprintf(buf, "%d", v);
    int back = 0;
    sscanf(buf, "%d", &back);
    return back;
}
