// bitops2.cpp - bit manipulation behavioral-test target for decompiler QA.
// Compile: cl /LD /Od /W3 bitops2.cpp
#include <stdint.h>

// ---- small plain structs ----------------------------------------------------
typedef struct BitField {
    uint32_t value;
    int      start;
    int      width;
} BitField;

typedef struct RunInfo {
    int max_run;
    int run_count;
    int total_ones;
} RunInfo;

// ---- single-bit operations --------------------------------------------------

extern "C" __declspec(dllexport) uint32_t bit_set(uint32_t v, int pos) {
    if (pos < 0 || pos > 31) {
        return v;
    }
    return v | (1u << pos);
}

extern "C" __declspec(dllexport) uint32_t bit_clear(uint32_t v, int pos) {
    if (pos < 0 || pos > 31) {
        return v;
    }
    return v & ~(1u << pos);
}

extern "C" __declspec(dllexport) uint32_t bit_toggle(uint32_t v, int pos) {
    if (pos < 0 || pos > 31) {
        return v;
    }
    return v ^ (1u << pos);
}

extern "C" __declspec(dllexport) int bit_test(uint32_t v, int pos) {
    if (pos < 0 || pos > 31) {
        return 0;
    }
    if (v & (1u << pos)) {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) uint32_t bit_assign(uint32_t v, int pos, int state) {
    if (pos < 0 || pos > 31) {
        return v;
    }
    if (state) {
        return v | (1u << pos);
    } else {
        return v & ~(1u << pos);
    }
}

// ---- counting bits ----------------------------------------------------------

extern "C" __declspec(dllexport) int popcount32(uint32_t v) {
    int count = 0;
    while (v) {
        v &= (v - 1);
        count++;
    }
    return count;
}

extern "C" __declspec(dllexport) int count_trailing_zeros(uint32_t v) {
    if (v == 0) {
        return 32;
    }
    int n = 0;
    while ((v & 1u) == 0) {
        v >>= 1;
        n++;
    }
    return n;
}

extern "C" __declspec(dllexport) int count_leading_zeros(uint32_t v) {
    if (v == 0) {
        return 32;
    }
    int n = 0;
    uint32_t mask = 0x80000000u;
    while ((v & mask) == 0) {
        n++;
        mask >>= 1;
    }
    return n;
}

extern "C" __declspec(dllexport) int parity32(uint32_t v) {
    int p = 0;
    for (int i = 0; i < 32; i++) {
        if (v & (1u << i)) {
            p ^= 1;
        }
    }
    return p;
}

extern "C" __declspec(dllexport) int count_zeros32(uint32_t v) {
    int zeros = 0;
    for (int i = 0; i < 32; i++) {
        if ((v & (1u << i)) == 0) {
            zeros++;
        }
    }
    return zeros;
}

// ---- reversal / swap --------------------------------------------------------

extern "C" __declspec(dllexport) uint32_t reverse_bits32(uint32_t v) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++) {
        r <<= 1;
        r |= (v & 1u);
        v >>= 1;
    }
    return r;
}

extern "C" __declspec(dllexport) uint8_t reverse_bits8(uint8_t v) {
    uint8_t r = 0;
    int i = 0;
    do {
        r = (uint8_t)((r << 1) | (v & 1u));
        v = (uint8_t)(v >> 1);
        i++;
    } while (i < 8);
    return r;
}

extern "C" __declspec(dllexport) uint32_t byte_swap32(uint32_t v) {
    uint32_t b0 = (v >> 0) & 0xFFu;
    uint32_t b1 = (v >> 8) & 0xFFu;
    uint32_t b2 = (v >> 16) & 0xFFu;
    uint32_t b3 = (v >> 24) & 0xFFu;
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

extern "C" __declspec(dllexport) uint64_t byte_swap64(uint64_t v) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) {
        r <<= 8;
        r |= (v & 0xFFu);
        v >>= 8;
    }
    return r;
}

extern "C" __declspec(dllexport) uint16_t nibble_swap16(uint16_t v) {
    uint16_t hi = (uint16_t)((v & 0x0F0Fu) << 4);
    uint16_t lo = (uint16_t)((v & 0xF0F0u) >> 4);
    return (uint16_t)(hi | lo);
}

// ---- bitfield extract / insert ---------------------------------------------

extern "C" __declspec(dllexport) uint32_t extract_field(uint32_t v, int start, int width) {
    if (start < 0 || width <= 0 || start + width > 32) {
        return 0;
    }
    uint32_t mask;
    if (width == 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = (1u << width) - 1u;
    }
    return (v >> start) & mask;
}

extern "C" __declspec(dllexport) uint32_t insert_field(uint32_t v, uint32_t field, int start, int width) {
    if (start < 0 || width <= 0 || start + width > 32) {
        return v;
    }
    uint32_t mask;
    if (width == 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = (1u << width) - 1u;
    }
    uint32_t cleared = v & ~(mask << start);
    return cleared | ((field & mask) << start);
}

extern "C" __declspec(dllexport) int extract_field_struct(const BitField* bf, uint32_t* out) {
    if (bf == 0 || out == 0) {
        return -1;
    }
    if (bf->start < 0 || bf->width <= 0 || bf->start + bf->width > 32) {
        return -1;
    }
    uint32_t mask;
    if (bf->width == 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = (1u << bf->width) - 1u;
    }
    *out = (bf->value >> bf->start) & mask;
    return 0;
}

// ---- power of two -----------------------------------------------------------

extern "C" __declspec(dllexport) int is_power_of_two(uint32_t v) {
    if (v == 0) {
        return 0;
    }
    if ((v & (v - 1)) == 0) {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) uint32_t next_power_of_two(uint32_t v) {
    if (v == 0) {
        return 1;
    }
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

extern "C" __declspec(dllexport) uint32_t nearest_power_of_two(uint32_t v) {
    if (v == 0) {
        return 1;
    }
    uint32_t hi = next_power_of_two(v);
    uint32_t lo = hi >> 1;
    if (lo == 0) {
        return hi;
    }
    uint32_t du = hi - v;
    uint32_t dl = v - lo;
    if (dl <= du) {
        return lo;
    }
    return hi;
}

// ---- rotate / sign extend ---------------------------------------------------

extern "C" __declspec(dllexport) uint32_t rotate_left32(uint32_t v, int amount) {
    int a = amount & 31;
    if (a == 0) {
        return v;
    }
    return (v << a) | (v >> (32 - a));
}

extern "C" __declspec(dllexport) uint32_t rotate_right32(uint32_t v, int amount) {
    int a = amount & 31;
    if (a == 0) {
        return v;
    }
    return (v >> a) | (v << (32 - a));
}

extern "C" __declspec(dllexport) int32_t sign_extend(uint32_t v, int bits) {
    if (bits <= 0 || bits >= 32) {
        return (int32_t)v;
    }
    uint32_t mask = (1u << bits) - 1u;
    uint32_t low = v & mask;
    uint32_t sign = 1u << (bits - 1);
    if (low & sign) {
        return (int32_t)(low | ~mask);
    }
    return (int32_t)low;
}

// ---- runs and interleave ----------------------------------------------------

extern "C" __declspec(dllexport) int count_runs_of_ones(uint32_t v, RunInfo* info) {
    int cur = 0;
    int max_run = 0;
    int runs = 0;
    int ones = 0;
    int prev = 0;
    for (int i = 0; i < 32; i++) {
        int bit = (v >> i) & 1u;
        if (bit) {
            ones++;
            cur++;
            if (cur > max_run) {
                max_run = cur;
            }
            if (prev == 0) {
                runs++;
            }
        } else {
            cur = 0;
        }
        prev = bit;
    }
    if (info) {
        info->max_run = max_run;
        info->run_count = runs;
        info->total_ones = ones;
    }
    return runs;
}

extern "C" __declspec(dllexport) uint32_t interleave_bits(uint16_t a, uint16_t b) {
    uint32_t r = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t abit = (uint32_t)((a >> i) & 1u);
        uint32_t bbit = (uint32_t)((b >> i) & 1u);
        r |= abit << (2 * i);
        r |= bbit << (2 * i + 1);
    }
    return r;
}

extern "C" __declspec(dllexport) int deinterleave_bits(uint32_t v, uint16_t* a, uint16_t* b) {
    if (a == 0 || b == 0) {
        return -1;
    }
    uint16_t ra = 0;
    uint16_t rb = 0;
    for (int i = 0; i < 16; i++) {
        ra = (uint16_t)(ra | (((v >> (2 * i)) & 1u) << i));
        rb = (uint16_t)(rb | (((v >> (2 * i + 1)) & 1u) << i));
    }
    *a = ra;
    *b = rb;
    return 0;
}

extern "C" __declspec(dllexport) int is_bit_palindrome(uint32_t v, int width) {
    if (width <= 0 || width > 32) {
        return 0;
    }
    int lo = 0;
    int hi = width - 1;
    while (lo < hi) {
        int blo = (v >> lo) & 1u;
        int bhi = (v >> hi) & 1u;
        if (blo != bhi) {
            return 0;
        }
        lo++;
        hi--;
    }
    return 1;
}

// ---- recursion / aggregate helpers -----------------------------------------

extern "C" __declspec(dllexport) int popcount_recursive(uint32_t v) {
    if (v == 0) {
        return 0;
    }
    return (int)(v & 1u) + popcount_recursive(v >> 1);
}

extern "C" __declspec(dllexport) int highest_set_bit(uint32_t v) {
    if (v == 0) {
        return -1;
    }
    int idx = 31;
    while (idx >= 0) {
        if (v & (1u << idx)) {
            return idx;
        }
        idx--;
    }
    return -1;
}

extern "C" __declspec(dllexport) int lowest_set_bit(uint32_t v) {
    if (v == 0) {
        return -1;
    }
    for (int i = 0; i < 32; i++) {
        if (v & (1u << i)) {
            return i;
        }
    }
    return -1;
}

extern "C" __declspec(dllexport) uint32_t merge_with_mask(uint32_t a, uint32_t b, uint32_t mask) {
    return (a & ~mask) | (b & mask);
}

extern "C" __declspec(dllexport) int classify_bits(uint32_t v) {
    int pc = popcount32(v);
    switch (pc) {
        case 0:
            return 0;
        case 32:
            return 4;
        default:
            break;
    }
    if (pc < 8) {
        return 1;
    } else if (pc < 24) {
        return 2;
    } else {
        return 3;
    }
}

extern "C" __declspec(dllexport) uint32_t apply_ops_array(uint32_t v, const int* ops, int n) {
    if (ops == 0 || n <= 0) {
        return v;
    }
    for (int i = 0; i < n; i++) {
        int op = ops[i];
        if (op < 0) {
            continue;
        }
        if (op >= 0 && op < 32) {
            v ^= (1u << op);
        } else {
            break;
        }
    }
    return v;
}

extern "C" __declspec(dllexport) int hamming_distance(uint32_t a, uint32_t b) {
    return popcount32(a ^ b);
}
