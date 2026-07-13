/* encoding.cpp - decompiler behavioral-test target.
 * Byte-buffer encoding primitives compiled with: cl /LD /Od
 * Pure deterministic C-style functions, each exported with a clean name.
 */
#include <stdint.h>

#define EXPORT extern "C" __declspec(dllexport)

/* ----- small plain structs used by some functions ----- */
typedef struct RleStats {
    int runs;
    int max_run;
    int total;
} RleStats;

typedef struct ByteSpan {
    const unsigned char *data;
    int len;
} ByteSpan;

/* --------------------------------------------------------------------- */
/* 1. hex_nibble: map a low nibble (0..15) to its ASCII hex digit.        */
EXPORT char hex_nibble(int v)
{
    int n = v & 0x0F;
    if (n < 10) {
        return (char)('0' + n);
    }
    return (char)('a' + (n - 10));
}

/* 2. nibble_from_hex: inverse of hex_nibble, returns -1 on bad input.    */
EXPORT int nibble_from_hex(char c)
{
    if (c >= '0' && c <= '9') {
        return (int)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (int)(c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return (int)(c - 'A') + 10;
    }
    return -1;
}

/* 3. byte_to_hex: write two lowercase hex chars for a byte.              */
EXPORT void byte_to_hex(unsigned char b, char *out)
{
    if (out == 0) {
        return;
    }
    out[0] = hex_nibble((b >> 4) & 0x0F);
    out[1] = hex_nibble(b & 0x0F);
}

/* 4. hex_to_byte: parse two hex chars; returns value or -1 on error.     */
EXPORT int hex_to_byte(char hi, char lo)
{
    int h = nibble_from_hex(hi);
    int l = nibble_from_hex(lo);
    if (h < 0 || l < 0) {
        return -1;
    }
    return (h << 4) | l;
}

/* 5. base64_index: index of a base64 char in the standard alphabet.      */
EXPORT int base64_index(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (int)(c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (int)(c - 'a') + 26;
    }
    if (c >= '0' && c <= '9') {
        return (int)(c - '0') + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* 6. base64_char: inverse of base64_index for 0..63.                     */
EXPORT char base64_char(int idx)
{
    int i = idx & 0x3F;
    if (i < 26) {
        return (char)('A' + i);
    }
    if (i < 52) {
        return (char)('a' + (i - 26));
    }
    if (i < 62) {
        return (char)('0' + (i - 52));
    }
    if (i == 62) {
        return '+';
    }
    return '/';
}

/* 7. rle_encode: run-length encode src into dst as (count,value) pairs.  */
/*    Returns number of bytes written to dst, or -1 on bad args.          */
EXPORT int rle_encode(const unsigned char *src, int n, unsigned char *dst, int cap)
{
    if (src == 0 || dst == 0 || n < 0 || cap < 0) {
        return -1;
    }
    int i = 0;
    int out = 0;
    while (i < n) {
        unsigned char val = src[i];
        int run = 1;
        while (i + run < n && src[i + run] == val && run < 255) {
            run++;
        }
        if (out + 2 > cap) {
            return -1;
        }
        dst[out++] = (unsigned char)run;
        dst[out++] = val;
        i += run;
    }
    return out;
}

/* 8. rle_decode_count: total decoded length of an RLE (count,value)      */
/*    stream without writing output. Returns -1 on malformed input.       */
EXPORT int rle_decode_count(const unsigned char *src, int n)
{
    if (src == 0 || n < 0) {
        return -1;
    }
    if ((n & 1) != 0) {
        return -1;
    }
    int total = 0;
    for (int i = 0; i < n; i += 2) {
        int run = (int)src[i];
        if (run == 0) {
            return -1;
        }
        total += run;
    }
    return total;
}

/* 9. rle_decode: expand an RLE stream into dst. Returns bytes written.   */
EXPORT int rle_decode(const unsigned char *src, int n, unsigned char *dst, int cap)
{
    if (src == 0 || dst == 0 || n < 0 || cap < 0) {
        return -1;
    }
    if ((n & 1) != 0) {
        return -1;
    }
    int out = 0;
    for (int i = 0; i < n; i += 2) {
        int run = (int)src[i];
        unsigned char val = src[i + 1];
        for (int k = 0; k < run; k++) {
            if (out >= cap) {
                return -1;
            }
            dst[out++] = val;
        }
    }
    return out;
}

/* 10. rle_analyze: gather run statistics over a buffer into stats.       */
EXPORT void rle_analyze(const unsigned char *src, int n, RleStats *stats)
{
    if (stats == 0) {
        return;
    }
    stats->runs = 0;
    stats->max_run = 0;
    stats->total = 0;
    if (src == 0 || n <= 0) {
        return;
    }
    int i = 0;
    while (i < n) {
        unsigned char val = src[i];
        int run = 1;
        while (i + run < n && src[i + run] == val) {
            run++;
        }
        stats->runs++;
        if (run > stats->max_run) {
            stats->max_run = run;
        }
        stats->total += run;
        i += run;
    }
}

/* 11. pack_4bit: pack n source bytes (low nibble each) into dst.         */
/*     Two source nibbles per output byte. Returns dst bytes written.     */
EXPORT int pack_4bit(const unsigned char *src, int n, unsigned char *dst, int cap)
{
    if (src == 0 || dst == 0 || n < 0 || cap < 0) {
        return -1;
    }
    int need = (n + 1) / 2;
    if (need > cap) {
        return -1;
    }
    int out = 0;
    for (int i = 0; i < n; i += 2) {
        unsigned char hi = (unsigned char)(src[i] & 0x0F);
        unsigned char lo = 0;
        if (i + 1 < n) {
            lo = (unsigned char)(src[i + 1] & 0x0F);
        }
        dst[out++] = (unsigned char)((hi << 4) | lo);
    }
    return out;
}

/* 12. unpack_4bit: expand packed nibbles back into one byte per nibble.  */
EXPORT int unpack_4bit(const unsigned char *src, int n, unsigned char *dst, int cap)
{
    if (src == 0 || dst == 0 || n < 0 || cap < 0) {
        return -1;
    }
    if (n * 2 > cap) {
        return -1;
    }
    int out = 0;
    for (int i = 0; i < n; i++) {
        dst[out++] = (unsigned char)((src[i] >> 4) & 0x0F);
        dst[out++] = (unsigned char)(src[i] & 0x0F);
    }
    return out;
}

/* 13. zigzag_encode: map signed 32-bit to unsigned for varint friendly.  */
EXPORT uint32_t zigzag_encode(int32_t v)
{
    return ((uint32_t)v << 1) ^ (uint32_t)(v >> 31);
}

/* 14. zigzag_decode: inverse of zigzag_encode.                           */
EXPORT int32_t zigzag_decode(uint32_t v)
{
    return (int32_t)((v >> 1) ^ (~(v & 1) + 1));
}

/* 15. zigzag_encode64: 64-bit variant of zigzag_encode.                  */
EXPORT uint64_t zigzag_encode64(int64_t v)
{
    return ((uint64_t)v << 1) ^ (uint64_t)(v >> 63);
}

/* 16. varint_len: number of bytes a LEB128 varint of v would occupy.     */
EXPORT int varint_len(uint64_t v)
{
    int len = 1;
    while (v >= 0x80) {
        v >>= 7;
        len++;
    }
    return len;
}

/* 17. varint_write: encode v as LEB128 into dst. Returns bytes written.  */
EXPORT int varint_write(uint64_t v, unsigned char *dst, int cap)
{
    if (dst == 0 || cap < 0) {
        return -1;
    }
    int out = 0;
    do {
        if (out >= cap) {
            return -1;
        }
        unsigned char b = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v != 0) {
            b = (unsigned char)(b | 0x80);
        }
        dst[out++] = b;
    } while (v != 0);
    return out;
}

/* 18. varint_read: decode a LEB128 varint from src into *out.            */
/*     Returns bytes consumed, or -1 on truncation/overflow.             */
EXPORT int varint_read(const unsigned char *src, int n, uint64_t *out)
{
    if (src == 0 || out == 0 || n < 0) {
        return -1;
    }
    uint64_t result = 0;
    int shift = 0;
    for (int i = 0; i < n; i++) {
        unsigned char b = src[i];
        if (shift > 63) {
            return -1;
        }
        result |= (uint64_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            *out = result;
            return i + 1;
        }
        shift += 7;
    }
    return -1;
}

/* 19. swap_endian32: reverse the byte order of a 32-bit value.           */
EXPORT uint32_t swap_endian32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

/* 20. swap_endian64: reverse the byte order of a 64-bit value.           */
EXPORT uint64_t swap_endian64(uint64_t v)
{
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) {
        r = (r << 8) | (v & 0xFFu);
        v >>= 8;
    }
    return r;
}

/* 21. bit_reverse_byte: reverse the 8 bits of a byte.                    */
EXPORT unsigned char bit_reverse_byte(unsigned char b)
{
    unsigned char r = 0;
    for (int i = 0; i < 8; i++) {
        r = (unsigned char)((r << 1) | (b & 1));
        b = (unsigned char)(b >> 1);
    }
    return r;
}

/* 22. bit_reverse32: reverse all 32 bits of a value.                     */
EXPORT uint32_t bit_reverse32(uint32_t v)
{
    uint32_t r = 0;
    int i = 0;
    do {
        r = (r << 1) | (v & 1u);
        v >>= 1;
        i++;
    } while (i < 32);
    return r;
}

/* 23. popcount8: count set bits in a byte using a small loop.            */
EXPORT int popcount8(unsigned char b)
{
    int count = 0;
    while (b != 0) {
        count += (b & 1);
        b = (unsigned char)(b >> 1);
    }
    return count;
}

/* 24. parity32: even-parity bit (0/1) of a 32-bit value.                 */
EXPORT int parity32(uint32_t v)
{
    int p = 0;
    while (v != 0) {
        p ^= 1;
        v &= (v - 1);
    }
    return p;
}

/* 25. checksum_xor: XOR fold a byte span; classifies via switch.         */
EXPORT int checksum_xor(const ByteSpan *span)
{
    if (span == 0 || span->data == 0 || span->len <= 0) {
        return -1;
    }
    unsigned char acc = 0;
    for (int i = 0; i < span->len; i++) {
        acc = (unsigned char)(acc ^ span->data[i]);
    }
    int bucket;
    switch (acc & 0x03) {
        case 0:  bucket = 1000; break;
        case 1:  bucket = 2000; break;
        case 2:  bucket = 3000; break;
        default: bucket = 4000; break;
    }
    return bucket + (int)acc;
}

/* 26. crc8_simple: a small CRC-8 (poly 0x07) over a buffer.              */
EXPORT unsigned char crc8_simple(const unsigned char *src, int n)
{
    unsigned char crc = 0;
    if (src == 0 || n <= 0) {
        return 0;
    }
    for (int i = 0; i < n; i++) {
        crc = (unsigned char)(crc ^ src[i]);
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80) {
                crc = (unsigned char)((crc << 1) ^ 0x07);
            } else {
                crc = (unsigned char)(crc << 1);
            }
        }
    }
    return crc;
}

/* 27. digit_sum_recursive: recursive decimal digit sum of an unsigned.   */
EXPORT int digit_sum_recursive(uint32_t v)
{
    if (v < 10) {
        return (int)v;
    }
    return (int)(v % 10) + digit_sum_recursive(v / 10);
}

/* 28. rotl32 / 29. rotr32: bit rotations with masked shift count.        */
EXPORT uint32_t rotl32(uint32_t v, int s)
{
    int k = s & 31;
    if (k == 0) {
        return v;
    }
    return (v << k) | (v >> (32 - k));
}

EXPORT uint32_t rotr32(uint32_t v, int s)
{
    int k = s & 31;
    if (k == 0) {
        return v;
    }
    return (v >> k) | (v << (32 - k));
}

/* 30. find_byte: first index of target in buffer, or -1 (continue demo). */
EXPORT int find_byte(const unsigned char *src, int n, unsigned char target)
{
    if (src == 0 || n <= 0) {
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (src[i] != target) {
            continue;
        }
        return i;
    }
    return -1;
}

/* 31. count_transitions: count value changes between adjacent bytes.     */
EXPORT int count_transitions(const unsigned char *src, int n)
{
    if (src == 0 || n <= 1) {
        return 0;
    }
    int changes = 0;
    int i = 1;
    do {
        if (src[i] != src[i - 1]) {
            changes++;
        }
        i++;
    } while (i < n);
    return changes;
}
