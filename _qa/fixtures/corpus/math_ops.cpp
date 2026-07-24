// math_ops.cpp - integer math + bit manipulation + recursion
// Decompiler test target. C-style C++ only.
#include <stdint.h>

extern "C" __declspec(dllexport) int add_i(int a, int b) {
    return a + b;
}

extern "C" __declspec(dllexport) int sub_i(int a, int b) {
    return a - b;
}

extern "C" __declspec(dllexport) int64_t mul_i(int a, int b) {
    int64_t wide = (int64_t)a * (int64_t)b;
    return wide;
}

extern "C" __declspec(dllexport) int divmod(int a, int b, int *rem) {
    if (b == 0) {
        if (rem) *rem = 0;
        return 0;
    }
    int q = a / b;
    int r = a % b;
    if (rem) *rem = r;
    return q;
}

extern "C" __declspec(dllexport) int abs_i(int x) {
    if (x < 0) return -x;
    return x;
}

extern "C" __declspec(dllexport) int sign_i(int x) {
    if (x > 0) return 1;
    if (x < 0) return -1;
    return 0;
}

extern "C" __declspec(dllexport) int clamp_i(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

extern "C" __declspec(dllexport) int min3(int a, int b, int c) {
    int m = a;
    if (b < m) m = b;
    if (c < m) m = c;
    return m;
}

extern "C" __declspec(dllexport) int max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}

extern "C" __declspec(dllexport) int gcd_i(int a, int b) {
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

extern "C" __declspec(dllexport) int64_t lcm_i(int a, int b) {
    int g = gcd_i(a, b);
    if (g == 0) return 0;
    int64_t prod = (int64_t)a / g;
    prod = prod * (int64_t)b;
    if (prod < 0) prod = -prod;
    return prod;
}

extern "C" __declspec(dllexport) int64_t int_pow(int base, int exp) {
    if (exp < 0) return 0;
    int64_t result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

extern "C" __declspec(dllexport) int64_t mod_pow(int64_t base, int64_t exp, int64_t mod) {
    if (mod <= 1) return 0;
    int64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

extern "C" __declspec(dllexport) int64_t factorial_iter(int n) {
    if (n < 0) return 0;
    int64_t f = 1;
    for (int i = 2; i <= n; i++) {
        f *= i;
    }
    return f;
}

extern "C" __declspec(dllexport) int64_t factorial_rec(int n) {
    if (n <= 1) return 1;
    return (int64_t)n * factorial_rec(n - 1);
}

extern "C" __declspec(dllexport) int64_t fib_iter(int n) {
    if (n < 0) return 0;
    int64_t a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        int64_t t = a + b;
        a = b;
        b = t;
    }
    return a;
}

extern "C" __declspec(dllexport) int64_t fib_rec(int n) {
    if (n < 2) return n < 0 ? 0 : n;
    return fib_rec(n - 1) + fib_rec(n - 2);
}

extern "C" __declspec(dllexport) int is_prime(int n) {
    if (n < 2) return 0;
    if (n < 4) return 1;
    if ((n & 1) == 0) return 0;
    for (int d = 3; (int64_t)d * d <= n; d += 2) {
        if (n % d == 0) return 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) int next_prime(int n) {
    int cand = n + 1;
    if (cand < 2) cand = 2;
    while (!is_prime(cand)) {
        cand++;
    }
    return cand;
}

extern "C" __declspec(dllexport) int sum_digits(int n) {
    if (n < 0) n = -n;
    int s = 0;
    do {
        s += n % 10;
        n /= 10;
    } while (n != 0);
    return s;
}

extern "C" __declspec(dllexport) int reverse_digits(int n) {
    int neg = 0;
    if (n < 0) { neg = 1; n = -n; }
    int r = 0;
    while (n != 0) {
        r = r * 10 + (n % 10);
        n /= 10;
    }
    return neg ? -r : r;
}

extern "C" __declspec(dllexport) int count_digits(int n) {
    if (n < 0) n = -n;
    int c = 0;
    do {
        c++;
        n /= 10;
    } while (n != 0);
    return c;
}

extern "C" __declspec(dllexport) int popcount32(uint32_t x) {
    int c = 0;
    while (x != 0) {
        c += (int)(x & 1u);
        x >>= 1;
    }
    return c;
}

extern "C" __declspec(dllexport) uint32_t reverse_bits32(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r <<= 1;
        r |= (x & 1u);
        x >>= 1;
    }
    return r;
}

extern "C" __declspec(dllexport) int is_pow2(uint32_t x) {
    if (x == 0) return 0;
    return (x & (x - 1)) == 0 ? 1 : 0;
}

extern "C" __declspec(dllexport) int isqrt_i(int64_t n) {
    if (n < 0) return -1;
    if (n < 2) return (int)n;
    int64_t lo = 1, hi = n, ans = 0;
    while (lo <= hi) {
        int64_t mid = lo + (hi - lo) / 2;
        if (mid * mid <= n) {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return (int)ans;
}

extern "C" __declspec(dllexport) int log2_floor(uint32_t x) {
    if (x == 0) return -1;
    int r = 0;
    while (x > 1) {
        x >>= 1;
        r++;
    }
    return r;
}

extern "C" __declspec(dllexport) uint32_t rotl32(uint32_t x, int n) {
    n &= 31;
    if (n == 0) return x;
    return (x << n) | (x >> (32 - n));
}

extern "C" __declspec(dllexport) uint32_t rotr32(uint32_t x, int n) {
    n &= 31;
    if (n == 0) return x;
    return (x >> n) | (x << (32 - n));
}

extern "C" __declspec(dllexport) int parity32(uint32_t x) {
    int p = 0;
    while (x != 0) {
        p ^= 1;
        x &= (x - 1);
    }
    return p;
}

extern "C" __declspec(dllexport) int collatz_steps(int64_t n) {
    if (n < 1) return -1;
    int steps = 0;
    while (n != 1) {
        if ((n & 1) == 0) {
            n /= 2;
        } else {
            n = 3 * n + 1;
        }
        steps++;
        if (steps > 100000) break;
    }
    return steps;
}

extern "C" __declspec(dllexport) uint32_t gray_encode(uint32_t x) {
    return x ^ (x >> 1);
}

extern "C" __declspec(dllexport) uint32_t gray_decode(uint32_t g) {
    uint32_t x = 0;
    while (g != 0) {
        x ^= g;
        g >>= 1;
    }
    return x;
}

extern "C" __declspec(dllexport) int64_t ackermann(int m, int n) {
    if (m < 0 || n < 0) return -1;
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, (int)ackermann(m, n - 1));
}

extern "C" __declspec(dllexport) int64_t nth_triangular(int n) {
    if (n < 0) return 0;
    return (int64_t)n * (n + 1) / 2;
}

extern "C" __declspec(dllexport) int digit_root(int n) {
    if (n < 0) n = -n;
    while (n >= 10) {
        int s = 0;
        while (n != 0) {
            s += n % 10;
            n /= 10;
        }
        n = s;
    }
    return n;
}

extern "C" __declspec(dllexport) int count_divisors(int n) {
    if (n <= 0) return 0;
    int c = 0;
    for (int d = 1; (int64_t)d * d <= n; d++) {
        if (n % d == 0) {
            c += 2;
            if (d * d == n) c--;
        }
    }
    return c;
}

extern "C" __declspec(dllexport) int classify_number(int n) {
    // 0 = zero, 1 = positive even, 2 = positive odd,
    // 3 = negative even, 4 = negative odd
    switch (n == 0 ? 0 : (n > 0 ? 1 : 2)) {
        case 0:
            return 0;
        case 1:
            return (n & 1) ? 2 : 1;
        case 2:
            return (n & 1) ? 4 : 3;
        default:
            return -1;
    }
}

extern "C" __declspec(dllexport) int64_t sum_range(int lo, int hi) {
    int64_t total = 0;
    for (int i = lo; i <= hi; i++) {
        if (i == 0) continue;
        total += i;
    }
    return total;
}

extern "C" __declspec(dllexport) int hamming_distance(uint32_t a, uint32_t b) {
    uint32_t x = a ^ b;
    return popcount32(x);
}

extern "C" __declspec(dllexport) int square(int x) {
    return x * x;
}

extern "C" __declspec(dllexport) int64_t cube(int x) {
    return (int64_t)x * x * x;
}

extern "C" __declspec(dllexport) int abs_diff(int a, int b) {
    if (a > b) return a - b;
    return b - a;
}

extern "C" __declspec(dllexport) int max_of_three_loop(int a, int b, int c) {
    int vals[3];
    vals[0] = a;
    vals[1] = b;
    vals[2] = c;
    int m = vals[0];
    for (int i = 1; i < 3; i++) {
        if (vals[i] > m) m = vals[i];
    }
    return m;
}

extern "C" __declspec(dllexport) int is_even(int x) {
    return (x & 1) == 0;
}

extern "C" __declspec(dllexport) int is_odd(int x) {
    return (x & 1) != 0;
}

extern "C" __declspec(dllexport) int gcd3(int a, int b, int c) {
    int g = gcd_i(a, b);
    return gcd_i(g, c);
}

extern "C" __declspec(dllexport) int64_t sum_squares(int n) {
    int64_t s = 0;
    for (int i = 1; i <= n; i++) {
        s += (int64_t)i * i;
    }
    return s;
}

extern "C" __declspec(dllexport) int count_multiples(int n, int k) {
    if (k == 0) return 0;
    int c = 0;
    for (int i = 1; i <= n; i++) {
        if (i % k == 0) c++;
    }
    return c;
}

extern "C" __declspec(dllexport) int clamp_u(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

extern "C" __declspec(dllexport) int swap_low_high_bytes(int x) {
    int lo = x & 0xFF;
    int hi = (x >> 8) & 0xFF;
    return (lo << 8) | hi;
}

extern "C" __declspec(dllexport) int triangular_loop(int n) {
    int t = 0;
    int i = 1;
    while (i <= n) {
        t += i;
        i++;
    }
    return t;
}
