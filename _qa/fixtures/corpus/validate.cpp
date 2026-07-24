/* validate.cpp - decompiler behavioral-test target
 * Heavy-branching validation / classification routines.
 * Compile: cl /LD /Od /W3 validate.cpp
 * Pure deterministic C-style functions, all exported with clean names.
 */
#include <stdint.h>

#define EXPORT extern "C" __declspec(dllexport)

/* ---- simple plain structs ---- */
typedef struct Point3 {
    int x;
    int y;
    int z;
} Point3;

typedef struct DateRec {
    int day;
    int month;
    int year;
} DateRec;

typedef struct ScoreRec {
    int total;
    int parts[4];
} ScoreRec;

/* ------------------------------------------------------------------ */
/* 1. validate_range: is value within [lo,hi] inclusive (handles swap) */
EXPORT int validate_range(int value, int lo, int hi)
{
    int a = lo;
    int b = hi;
    if (a > b) {
        int t = a;
        a = b;
        b = t;
    }
    if (value < a) {
        return 0;
    }
    if (value > b) {
        return 0;
    }
    return 1;
}

/* 2. classify_triangle_sides: 0 invalid,1 equilateral,2 isosceles,3 scalene */
EXPORT int classify_triangle_sides(int s1, int s2, int s3)
{
    if (s1 <= 0 || s2 <= 0 || s3 <= 0) {
        return 0;
    }
    if (s1 + s2 <= s3) {
        return 0;
    }
    if (s2 + s3 <= s1) {
        return 0;
    }
    if (s1 + s3 <= s2) {
        return 0;
    }
    if (s1 == s2 && s2 == s3) {
        return 1;
    }
    if (s1 == s2 || s2 == s3 || s1 == s3) {
        return 2;
    }
    return 3;
}

/* 3. password_score: score from length and character classes */
EXPORT int password_score(int len, int has_lower, int has_upper,
                          int has_digit, int has_symbol)
{
    int score = 0;
    if (len >= 8) {
        score += 2;
    } else if (len >= 6) {
        score += 1;
    } else {
        score -= 1;
    }
    int classes = 0;
    if (has_lower) classes++;
    if (has_upper) classes++;
    if (has_digit) classes++;
    if (has_symbol) classes++;
    switch (classes) {
        case 4: score += 4; break;
        case 3: score += 3; break;
        case 2: score += 1; break;
        default: break;
    }
    if (len >= 12 && classes >= 3) {
        score += 2;
    }
    if (score < 0) {
        score = 0;
    }
    return score;
}

/* 4. grade_curve: map raw 0..100 plus curve bonus to letter 0=F..4=A */
EXPORT int grade_curve(int raw, int curve)
{
    int v = raw + curve;
    if (v < 0) v = 0;
    if (v > 100) v = 100;
    if (v >= 90) return 4;
    if (v >= 80) return 3;
    if (v >= 70) return 2;
    if (v >= 60) return 1;
    return 0;
}

/* 5. leap_check: gregorian leap year test */
EXPORT int leap_check(int year)
{
    if (year <= 0) {
        return 0;
    }
    if (year % 400 == 0) {
        return 1;
    }
    if (year % 100 == 0) {
        return 0;
    }
    if (year % 4 == 0) {
        return 1;
    }
    return 0;
}

/* 6. ip_octet_valid: all four octets in 0..255 */
EXPORT int ip_octet_valid(int o1, int o2, int o3, int o4)
{
    int oct[4];
    oct[0] = o1;
    oct[1] = o2;
    oct[2] = o3;
    oct[3] = o4;
    int i;
    for (i = 0; i < 4; i++) {
        if (oct[i] < 0 || oct[i] > 255) {
            return 0;
        }
    }
    return 1;
}

/* 7. luhn_check_small: validate up to 19 digits via Luhn algorithm */
EXPORT int luhn_check_small(const int *digits, int count)
{
    if (digits == 0 || count <= 0 || count > 19) {
        return 0;
    }
    int sum = 0;
    int dbl = 0;
    int i = count - 1;
    while (i >= 0) {
        int d = digits[i];
        if (d < 0 || d > 9) {
            return 0;
        }
        if (dbl) {
            d = d * 2;
            if (d > 9) {
                d -= 9;
            }
        }
        sum += d;
        dbl = !dbl;
        i--;
    }
    if (sum % 10 == 0) {
        return 1;
    }
    return 0;
}

/* 8. classify_angle: 0 invalid,1 zero,2 acute,3 right,4 obtuse,5 straight,6 reflex */
EXPORT int classify_angle(int deg)
{
    if (deg < 0 || deg > 360) {
        return 0;
    }
    if (deg == 0 || deg == 360) {
        return 1;
    }
    if (deg == 90) {
        return 3;
    }
    if (deg == 180) {
        return 5;
    }
    if (deg < 90) {
        return 2;
    }
    if (deg < 180) {
        return 4;
    }
    return 6;
}

/* 9. bmi_bucket_int: bmi scaled by 10 (e.g. 244 => 24.4) -> bucket */
EXPORT int bmi_bucket_int(int bmi_x10)
{
    if (bmi_x10 <= 0) {
        return -1;
    }
    if (bmi_x10 < 185) {
        return 0; /* underweight */
    } else if (bmi_x10 < 250) {
        return 1; /* normal */
    } else if (bmi_x10 < 300) {
        return 2; /* overweight */
    } else {
        return 3; /* obese */
    }
}

/* 10. day_of_week_zeller: 0=Saturday..6=Friday (Zeller congruence) */
EXPORT int day_of_week_zeller(int day, int month, int year)
{
    if (day < 1 || day > 31 || month < 1 || month > 12 || year < 1) {
        return -1;
    }
    int m = month;
    int y = year;
    if (m < 3) {
        m += 12;
        y -= 1;
    }
    int k = y % 100;
    int j = y / 100;
    int h = (day + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 + 5 * j) % 7;
    if (h < 0) {
        h += 7;
    }
    return h;
}

/* 11. season: northern hemisphere season 0=winter,1=spring,2=summer,3=autumn */
EXPORT int season(int month, int day)
{
    if (month < 1 || month > 12 || day < 1 || day > 31) {
        return -1;
    }
    switch (month) {
        case 12:
        case 1:
        case 2:
            return 0;
        case 3:
            return (day < 20) ? 0 : 1;
        case 4:
        case 5:
            return 1;
        case 6:
            return (day < 21) ? 1 : 2;
        case 7:
        case 8:
            return 2;
        case 9:
            return (day < 22) ? 2 : 3;
        case 10:
        case 11:
            return 3;
        default:
            return -1;
    }
}

/* 12. clamp_chain: clamp through a chain of bounds applied in order */
EXPORT int clamp_chain(int value, const int *bounds, int pair_count)
{
    if (bounds == 0 || pair_count <= 0) {
        return value;
    }
    int v = value;
    int i;
    for (i = 0; i < pair_count; i++) {
        int lo = bounds[i * 2];
        int hi = bounds[i * 2 + 1];
        if (lo > hi) {
            continue;
        }
        if (v < lo) {
            v = lo;
        } else if (v > hi) {
            v = hi;
        }
    }
    return v;
}

/* ------------------------------------------------------------------ */
/* additional helpers to widen the corpus                              */

/* 13. gcd via recursion */
EXPORT int gcd_rec(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    if (b == 0) {
        return a;
    }
    return gcd_rec(b, a % b);
}

/* 14. count_set_bits */
EXPORT int count_set_bits(uint32_t v)
{
    int n = 0;
    while (v != 0) {
        n += (int)(v & 1u);
        v >>= 1;
    }
    return n;
}

/* 15. is_prime trial division */
EXPORT int is_prime(int n)
{
    if (n < 2) {
        return 0;
    }
    if (n < 4) {
        return 1;
    }
    if (n % 2 == 0) {
        return 0;
    }
    int i;
    for (i = 3; i * i <= n; i += 2) {
        if (n % i == 0) {
            return 0;
        }
    }
    return 1;
}

/* 16. classify_char: 0 other,1 lower,2 upper,3 digit,4 space */
EXPORT int classify_char(int c)
{
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 2;
    if (c >= '0' && c <= '9') return 3;
    if (c == ' ' || c == '\t' || c == '\n') return 4;
    return 0;
}

/* 17. validate_date: full calendar validity using leap_check */
EXPORT int validate_date(const DateRec *d)
{
    if (d == 0) {
        return 0;
    }
    if (d->year < 1 || d->month < 1 || d->month > 12) {
        return 0;
    }
    int mdays[12];
    mdays[0] = 31; mdays[1] = 28; mdays[2] = 31; mdays[3] = 30;
    mdays[4] = 31; mdays[5] = 30; mdays[6] = 31; mdays[7] = 31;
    mdays[8] = 30; mdays[9] = 31; mdays[10] = 30; mdays[11] = 31;
    int limit = mdays[d->month - 1];
    if (d->month == 2 && leap_check(d->year)) {
        limit = 29;
    }
    if (d->day < 1 || d->day > limit) {
        return 0;
    }
    return 1;
}

/* 18. manhattan distance between two Point3 */
EXPORT int manhattan3(const Point3 *a, const Point3 *b)
{
    if (a == 0 || b == 0) {
        return -1;
    }
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    int dz = a->z - b->z;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    if (dz < 0) dz = -dz;
    return dx + dy + dz;
}

/* 19. running checksum with mixed loop forms */
EXPORT uint32_t mix_checksum(const uint8_t *buf, int len)
{
    if (buf == 0 || len <= 0) {
        return 0u;
    }
    uint32_t h = 2166136261u;
    int i = 0;
    do {
        h ^= (uint32_t)buf[i];
        h *= 16777619u;
        h += (h << 3);
        h ^= (h >> 11);
        i++;
    } while (i < len);
    return h;
}

/* 20. score_aggregate: fill struct, return total */
EXPORT int score_aggregate(ScoreRec *out, int a, int b, int c, int d)
{
    if (out == 0) {
        return -1;
    }
    out->parts[0] = a;
    out->parts[1] = b;
    out->parts[2] = c;
    out->parts[3] = d;
    int total = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int p = out->parts[i];
        if (p < 0) {
            p = 0;
        }
        total += p;
    }
    out->total = total;
    return total;
}

/* 21. nested loop matrix trace check (square, side<=8) */
EXPORT int matrix_diag_dominant(const int *m, int side)
{
    if (m == 0 || side <= 0 || side > 8) {
        return 0;
    }
    int r;
    for (r = 0; r < side; r++) {
        int diag = m[r * side + r];
        if (diag < 0) {
            diag = -diag;
        }
        int sumoff = 0;
        int col;
        for (col = 0; col < side; col++) {
            if (col == r) {
                continue;
            }
            int v = m[r * side + col];
            if (v < 0) {
                v = -v;
            }
            sumoff += v;
        }
        if (diag < sumoff) {
            return 0;
        }
    }
    return 1;
}

/* 22. classify_number sign/parity packed: bit0 nonzero,bit1 negative,bit2 odd */
EXPORT int classify_number(int n)
{
    int flags = 0;
    if (n != 0) {
        flags |= 1;
    }
    if (n < 0) {
        flags |= 2;
    }
    int mod = n % 2;
    if (mod != 0) {
        flags |= 4;
    }
    return flags;
}

/* 23. fib iterative with early bounds */
EXPORT int64_t fib_iter(int n)
{
    if (n < 0) {
        return -1;
    }
    if (n < 2) {
        return (int64_t)n;
    }
    int64_t a = 0;
    int64_t b = 1;
    int i;
    for (i = 2; i <= n; i++) {
        int64_t c = a + b;
        a = b;
        b = c;
    }
    return b;
}

/* 24. clamp_byte simple */
EXPORT int clamp_byte(int v)
{
    if (v < 0) {
        return 0;
    } else if (v > 255) {
        return 255;
    }
    return v;
}
