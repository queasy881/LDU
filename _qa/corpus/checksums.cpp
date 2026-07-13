/* checksums.cpp
 * Decompiler behavioral-test target: hashing/checksums over byte buffers.
 * Compile: cl /LD /Od /W3 checksums.cpp
 * Pure deterministic C-style functions, all exported with clean names.
 */

#include <stdint.h>

/* ----- small helper-ish exported primitives ----- */

extern "C" __declspec(dllexport) uint32_t rotl32(uint32_t x, int r)
{
    r &= 31;
    if (r == 0)
        return x;
    return (x << r) | (x >> (32 - r));
}

extern "C" __declspec(dllexport) uint32_t rotr32(uint32_t x, int r)
{
    r &= 31;
    if (r == 0)
        return x;
    return (x >> r) | (x << (32 - r));
}

extern "C" __declspec(dllexport) uint32_t mix32(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

/* ----- classic string/byte hashes ----- */

extern "C" __declspec(dllexport) uint32_t djb2(const unsigned char* d, int n)
{
    uint32_t h = 5381U;
    if (d == 0 || n <= 0)
        return h;
    for (int i = 0; i < n; ++i)
    {
        h = ((h << 5) + h) + (uint32_t)d[i];
    }
    return h;
}

extern "C" __declspec(dllexport) uint32_t fnv1a(const unsigned char* d, int n)
{
    uint32_t h = 2166136261U;
    if (d == 0)
        return h;
    int i = 0;
    while (i < n)
    {
        h ^= (uint32_t)d[i];
        h *= 16777619U;
        ++i;
    }
    return h;
}

extern "C" __declspec(dllexport) uint32_t sdbm(const unsigned char* d, int n)
{
    uint32_t h = 0U;
    if (d == 0 || n <= 0)
        return h;
    int i = 0;
    do
    {
        h = (uint32_t)d[i] + (h << 6) + (h << 16) - h;
        ++i;
    } while (i < n);
    return h;
}

/* ----- simple accumulating sums ----- */

extern "C" __declspec(dllexport) uint8_t sum8(const unsigned char* d, int n)
{
    uint8_t s = 0;
    if (d == 0)
        return s;
    for (int i = 0; i < n; ++i)
        s = (uint8_t)(s + d[i]);
    return s;
}

extern "C" __declspec(dllexport) uint16_t sum16(const unsigned char* d, int n)
{
    uint16_t s = 0;
    if (d == 0 || n <= 0)
        return s;
    for (int i = 0; i < n; ++i)
        s = (uint16_t)(s + d[i]);
    return s;
}

extern "C" __declspec(dllexport) uint32_t sum32(const unsigned char* d, int n)
{
    uint32_t s = 0U;
    if (d == 0)
        return s;
    for (int i = 0; i < n; ++i)
        s += (uint32_t)d[i];
    return s;
}

extern "C" __declspec(dllexport) uint32_t xor_fold(const unsigned char* d, int n)
{
    uint32_t acc = 0U;
    if (d == 0 || n <= 0)
        return acc;
    for (int i = 0; i < n; ++i)
    {
        uint32_t shift = (uint32_t)((i & 3) * 8);
        acc ^= ((uint32_t)d[i]) << shift;
    }
    return acc;
}

extern "C" __declspec(dllexport) uint8_t parity_byte(const unsigned char* d, int n)
{
    uint8_t p = 0;
    if (d == 0)
        return p;
    for (int i = 0; i < n; ++i)
    {
        unsigned char b = d[i];
        while (b)
        {
            p ^= 1;
            b &= (unsigned char)(b - 1);
        }
    }
    return p;
}

/* ----- adler32-lite (small modulus) ----- */

extern "C" __declspec(dllexport) uint32_t adler32_lite(const unsigned char* d, int n)
{
    uint32_t a = 1U;
    uint32_t b = 0U;
    const uint32_t MOD = 65521U;
    if (d == 0 || n <= 0)
        return (b << 16) | a;
    for (int i = 0; i < n; ++i)
    {
        a = (a + (uint32_t)d[i]) % MOD;
        b = (b + a) % MOD;
    }
    return (b << 16) | a;
}

/* ----- CRC variants (bitwise, no tables) ----- */

extern "C" __declspec(dllexport) uint8_t crc8(const unsigned char* d, int n)
{
    uint8_t crc = 0x00;
    if (d == 0)
        return crc;
    for (int i = 0; i < n; ++i)
    {
        crc ^= d[i];
        for (int j = 0; j < 8; ++j)
        {
            if (crc & 0x80)
                crc = (uint8_t)((crc << 1) ^ 0x07);
            else
                crc = (uint8_t)(crc << 1);
        }
    }
    return crc;
}

extern "C" __declspec(dllexport) uint16_t crc16_ccitt(const unsigned char* d, int n)
{
    uint16_t crc = 0xFFFF;
    if (d == 0 || n <= 0)
        return crc;
    for (int i = 0; i < n; ++i)
    {
        crc ^= (uint16_t)((uint16_t)d[i] << 8);
        for (int j = 0; j < 8; ++j)
        {
            if (crc & 0x8000)
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            else
                crc = (uint16_t)(crc << 1);
        }
    }
    return crc;
}

extern "C" __declspec(dllexport) uint32_t crc32_bitwise(const unsigned char* d, int n)
{
    uint32_t crc = 0xFFFFFFFFU;
    if (d == 0)
        return ~crc;
    for (int i = 0; i < n; ++i)
    {
        crc ^= (uint32_t)d[i];
        for (int j = 0; j < 8; ++j)
        {
            if (crc & 1U)
                crc = (crc >> 1) ^ 0xEDB88320U;
            else
                crc = crc >> 1;
        }
    }
    return ~crc;
}

/* ----- rolling hash (Rabin-Karp style) ----- */

extern "C" __declspec(dllexport) uint32_t rolling_hash(const unsigned char* d, int n)
{
    uint32_t h = 0U;
    const uint32_t base = 257U;
    if (d == 0 || n <= 0)
        return h;
    for (int i = 0; i < n; ++i)
        h = h * base + (uint32_t)d[i] + 1U;
    return h;
}

extern "C" __declspec(dllexport) uint32_t rolling_window(const unsigned char* d, int n, int win)
{
    if (d == 0 || n <= 0 || win <= 0)
        return 0U;
    if (win > n)
        win = n;
    const uint32_t base = 131U;
    uint32_t pow = 1U;
    for (int k = 1; k < win; ++k)
        pow *= base;
    uint32_t h = 0U;
    for (int i = 0; i < win; ++i)
        h = h * base + (uint32_t)d[i];
    uint32_t best = h;
    for (int i = win; i < n; ++i)
    {
        h = (h - (uint32_t)d[i - win] * pow) * base + (uint32_t)d[i];
        if (h > best)
            best = h;
    }
    return best;
}

/* ----- jenkins one-at-a-time ----- */

extern "C" __declspec(dllexport) uint32_t jenkins_one_at_a_time(const unsigned char* d, int n)
{
    uint32_t h = 0U;
    if (d == 0 || n <= 0)
        return h;
    for (int i = 0; i < n; ++i)
    {
        h += (uint32_t)d[i];
        h += (h << 10);
        h ^= (h >> 6);
    }
    h += (h << 3);
    h ^= (h >> 11);
    h += (h << 15);
    return h;
}

/* ----- recursive checksum variant ----- */

extern "C" __declspec(dllexport) uint32_t sum32_recursive(const unsigned char* d, int n)
{
    if (d == 0 || n <= 0)
        return 0U;
    return (uint32_t)d[n - 1] + sum32_recursive(d, n - 1);
}

/* ----- combined / dispatch helpers using switch ----- */

extern "C" __declspec(dllexport) uint32_t checksum_select(const unsigned char* d, int n, int which)
{
    switch (which)
    {
    case 0:
        return djb2(d, n);
    case 1:
        return fnv1a(d, n);
    case 2:
        return sdbm(d, n);
    case 3:
        return sum32(d, n);
    case 4:
        return adler32_lite(d, n);
    case 5:
        return jenkins_one_at_a_time(d, n);
    default:
        return crc32_bitwise(d, n);
    }
}

/* nibble-folding fold with nested loop and continue */

extern "C" __declspec(dllexport) uint32_t nibble_fold(const unsigned char* d, int n)
{
    uint32_t acc = 0U;
    if (d == 0 || n <= 0)
        return acc;
    for (int i = 0; i < n; ++i)
    {
        unsigned char b = d[i];
        for (int k = 0; k < 2; ++k)
        {
            uint32_t nib = (k == 0) ? (uint32_t)(b & 0x0F) : (uint32_t)(b >> 4);
            if (nib == 0)
                continue;
            acc = rotl32(acc, 3) + nib;
        }
    }
    return acc;
}

/* weighted modular checksum (Luhn-ish) */

extern "C" __declspec(dllexport) uint32_t weighted_mod(const unsigned char* d, int n, uint32_t mod)
{
    if (d == 0 || n <= 0)
        return 0U;
    if (mod == 0)
        mod = 251U;
    uint32_t acc = 0U;
    for (int i = 0; i < n; ++i)
    {
        uint32_t w = (uint32_t)((i % 4) + 1);
        acc = (acc + (uint32_t)d[i] * w) % mod;
    }
    return acc;
}

/* two-pointer style: hash from both ends until they meet */

extern "C" __declspec(dllexport) uint32_t fold_ends(const unsigned char* d, int n)
{
    uint32_t h = 0x9E3779B9U;
    if (d == 0 || n <= 0)
        return h;
    int lo = 0;
    int hi = n - 1;
    while (lo <= hi)
    {
        if (lo == hi)
        {
            h ^= mix32((uint32_t)d[lo]);
            break;
        }
        uint32_t pair = ((uint32_t)d[lo] << 8) | (uint32_t)d[hi];
        h = rotr32(h, 5) ^ mix32(pair);
        ++lo;
        --hi;
    }
    return h;
}

/* struct-based digest: write multiple results through a pointer param */

struct Digest
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
};

extern "C" __declspec(dllexport) int compute_digest(const unsigned char* data, int n, Digest* out)
{
    if (out == 0)
        return -1;
    out->a = djb2(data, n);
    out->b = fnv1a(data, n);
    out->c = crc32_bitwise(data, n);
    out->d = jenkins_one_at_a_time(data, n);
    if (data == 0 || n <= 0)
        return 0;
    return n;
}

/* verify a 32-bit checksum against an expected value */

extern "C" __declspec(dllexport) int verify_checksum(const unsigned char* d, int n, int which, uint32_t expected)
{
    uint32_t got = checksum_select(d, n, which);
    if (got == expected)
        return 1;
    return 0;
}

/* count distinct byte values, struct-free, fixed array */

extern "C" __declspec(dllexport) int distinct_bytes(const unsigned char* d, int n)
{
    if (d == 0 || n <= 0)
        return 0;
    unsigned char seen[256];
    for (int i = 0; i < 256; ++i)
        seen[i] = 0;
    int count = 0;
    for (int i = 0; i < n; ++i)
    {
        unsigned char b = d[i];
        if (seen[b] == 0)
        {
            seen[b] = 1;
            ++count;
        }
    }
    return count;
}

/* checksum of a checksum: chain two passes */

extern "C" __declspec(dllexport) uint32_t double_hash(const unsigned char* d, int n)
{
    uint32_t first = fnv1a(d, n);
    unsigned char tmp[4];
    tmp[0] = (unsigned char)(first & 0xFF);
    tmp[1] = (unsigned char)((first >> 8) & 0xFF);
    tmp[2] = (unsigned char)((first >> 16) & 0xFF);
    tmp[3] = (unsigned char)((first >> 24) & 0xFF);
    return djb2(tmp, 4) ^ mix32(first);
}
