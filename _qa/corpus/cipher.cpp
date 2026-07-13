/* cipher.cpp - simple ciphers on char buffers.
 * Decompiler behavioral-test target. Compiled with: cl /LD /Od
 * Pure deterministic C-style functions, all dllexported with clean names.
 */
#include <stdint.h>

/* ----- small character classification helpers ----- */

extern "C" __declspec(dllexport) int is_upper(int c)
{
    if (c >= 'A' && c <= 'Z')
        return 1;
    return 0;
}

extern "C" __declspec(dllexport) int is_lower(int c)
{
    if (c >= 'a' && c <= 'z')
        return 1;
    return 0;
}

extern "C" __declspec(dllexport) int is_alpha(int c)
{
    if (is_upper(c))
        return 1;
    if (is_lower(c))
        return 1;
    return 0;
}

extern "C" __declspec(dllexport) int to_toggle_case(int c)
{
    if (is_upper(c))
        return c - 'A' + 'a';
    if (is_lower(c))
        return c - 'a' + 'A';
    return c;
}

extern "C" __declspec(dllexport) int alpha_index(int c)
{
    if (is_upper(c))
        return c - 'A';
    if (is_lower(c))
        return c - 'a';
    return -1;
}

/* ----- single-character shift primitives ----- */

extern "C" __declspec(dllexport) int caesar_shift_char(int c, int shift)
{
    int s = shift % 26;
    if (s < 0)
        s += 26;
    if (is_upper(c)) {
        int v = (c - 'A' + s) % 26;
        return 'A' + v;
    }
    if (is_lower(c)) {
        int v = (c - 'a' + s) % 26;
        return 'a' + v;
    }
    return c;
}

extern "C" __declspec(dllexport) int caesar_unshift_char(int c, int shift)
{
    int s = shift % 26;
    if (s < 0)
        s += 26;
    return caesar_shift_char(c, 26 - s);
}

/* ----- buffer-level Caesar ciphers ----- */

extern "C" __declspec(dllexport) int caesar_shift(char *buf, int len, int shift)
{
    int i;
    int changed = 0;
    if (buf == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        int oc = (unsigned char)buf[i];
        int nc = caesar_shift_char(oc, shift);
        if (nc != oc)
            ++changed;
        buf[i] = (char)nc;
    }
    return changed;
}

extern "C" __declspec(dllexport) int caesar_unshift(char *buf, int len, int shift)
{
    int i;
    int changed = 0;
    if (buf == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        int oc = (unsigned char)buf[i];
        int nc = caesar_unshift_char(oc, shift);
        if (nc != oc)
            ++changed;
        buf[i] = (char)nc;
    }
    return changed;
}

/* ----- ROT13 ----- */

extern "C" __declspec(dllexport) int rot13_char(int c)
{
    return caesar_shift_char(c, 13);
}

extern "C" __declspec(dllexport) int rot13(char *buf, int len)
{
    int i = 0;
    if (buf == 0)
        return 0;
    while (i < len) {
        buf[i] = (char)rot13_char((unsigned char)buf[i]);
        ++i;
    }
    return i;
}

/* ----- Atbash ----- */

extern "C" __declspec(dllexport) int atbash_char(int c)
{
    if (is_upper(c))
        return 'Z' - (c - 'A');
    if (is_lower(c))
        return 'z' - (c - 'a');
    return c;
}

extern "C" __declspec(dllexport) int atbash(char *buf, int len)
{
    int i;
    int n = 0;
    if (buf == 0 || len < 0)
        return 0;
    for (i = 0; i < len; ++i) {
        int oc = (unsigned char)buf[i];
        if (is_alpha(oc)) {
            buf[i] = (char)atbash_char(oc);
            ++n;
        }
    }
    return n;
}

/* ----- XOR cipher ----- */

extern "C" __declspec(dllexport) int xor_cipher(char *buf, int len, int key)
{
    int i;
    unsigned char k = (unsigned char)(key & 0xFF);
    if (buf == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        unsigned char v = (unsigned char)buf[i];
        v = (unsigned char)(v ^ k);
        buf[i] = (char)v;
    }
    return len;
}

extern "C" __declspec(dllexport) uint32_t xor_checksum(const char *buf, int len, int key)
{
    int i;
    uint32_t acc = 0;
    unsigned char k = (unsigned char)(key & 0xFF);
    if (buf == 0)
        return 0;
    for (i = 0; i < len; ++i) {
        unsigned char v = (unsigned char)buf[i];
        acc += (uint32_t)(v ^ k);
        acc = (acc << 1) | (acc >> 31);
    }
    return acc;
}

/* ----- Vigenere ----- */

extern "C" __declspec(dllexport) int vigenere_step(int c, int keychar, int decrypt)
{
    int ki = alpha_index(keychar);
    if (ki < 0)
        return c;
    if (decrypt)
        return caesar_unshift_char(c, ki);
    return caesar_shift_char(c, ki);
}

extern "C" __declspec(dllexport) int vigenere_apply(char *buf, int len,
                                                    const char *key, int klen,
                                                    int decrypt)
{
    int i;
    int kpos = 0;
    int done = 0;
    if (buf == 0 || key == 0 || len <= 0 || klen <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        int oc = (unsigned char)buf[i];
        if (!is_alpha(oc))
            continue;
        {
            int kc = (unsigned char)key[kpos % klen];
            buf[i] = (char)vigenere_step(oc, kc, decrypt);
            ++kpos;
            ++done;
        }
    }
    return done;
}

/* ----- substitution cipher via 256-entry map ----- */

extern "C" __declspec(dllexport) int sub_cipher_apply(char *buf, int len, const char *map)
{
    int i;
    if (buf == 0 || map == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        unsigned char idx = (unsigned char)buf[i];
        buf[i] = map[idx];
    }
    return len;
}

extern "C" __declspec(dllexport) int sub_cipher_invert(const char *map, char *out)
{
    int i;
    if (map == 0 || out == 0)
        return 0;
    for (i = 0; i < 256; ++i)
        out[i] = (char)i;
    for (i = 0; i < 256; ++i) {
        unsigned char to = (unsigned char)map[i];
        out[to] = (char)i;
    }
    return 256;
}

/* ----- analysis helpers ----- */

extern "C" __declspec(dllexport) int count_shifted_equal(const char *a, const char *b,
                                                         int len, int shift)
{
    int i;
    int eq = 0;
    if (a == 0 || b == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i) {
        int sc = caesar_shift_char((unsigned char)a[i], shift);
        if (sc == (unsigned char)b[i])
            ++eq;
    }
    return eq;
}

extern "C" __declspec(dllexport) int reverse_words_count(char *buf, int len)
{
    int i = 0;
    int words = 0;
    if (buf == 0 || len <= 0)
        return 0;
    while (i < len) {
        int start;
        int end;
        /* skip spaces */
        while (i < len && buf[i] == ' ')
            ++i;
        if (i >= len)
            break;
        start = i;
        while (i < len && buf[i] != ' ')
            ++i;
        end = i - 1;
        ++words;
        /* reverse this word in place */
        while (start < end) {
            char t = buf[start];
            buf[start] = buf[end];
            buf[end] = t;
            ++start;
            --end;
        }
    }
    return words;
}

extern "C" __declspec(dllexport) int letter_histogram(const char *buf, int len, int *hist26)
{
    int i;
    int total = 0;
    if (buf == 0 || hist26 == 0)
        return 0;
    for (i = 0; i < 26; ++i)
        hist26[i] = 0;
    for (i = 0; i < len; ++i) {
        int idx = alpha_index((unsigned char)buf[i]);
        if (idx >= 0) {
            hist26[idx]++;
            ++total;
        }
    }
    return total;
}

extern "C" __declspec(dllexport) int best_caesar_shift(const char *buf, int len)
{
    int s;
    int bestShift = 0;
    int bestScore = -1;
    if (buf == 0 || len <= 0)
        return 0;
    for (s = 0; s < 26; ++s) {
        int i;
        int score = 0;
        for (i = 0; i < len; ++i) {
            int c = caesar_shift_char((unsigned char)buf[i], s);
            switch (c) {
            case 'E':
            case 'e':
            case 'T':
            case 't':
            case 'A':
            case 'a':
                score += 2;
                break;
            case 'Z':
            case 'z':
            case 'Q':
            case 'q':
                score -= 1;
                break;
            default:
                break;
            }
        }
        if (score > bestScore) {
            bestScore = score;
            bestShift = s;
        }
    }
    return bestShift;
}

/* ----- struct-based rolling state cipher ----- */

typedef struct CipherState {
    uint32_t seed;
    int32_t pos;
    int32_t shift;
} CipherState;

extern "C" __declspec(dllexport) void cipher_state_init(CipherState *st, uint32_t seed, int shift)
{
    if (st == 0)
        return;
    st->seed = seed;
    st->pos = 0;
    st->shift = shift;
}

extern "C" __declspec(dllexport) int cipher_state_next(CipherState *st, int c)
{
    int eff;
    if (st == 0)
        return c;
    st->seed = st->seed * 1664525u + 1013904223u;
    eff = (int)((st->seed >> 24) & 0x1F) + st->shift + st->pos;
    st->pos++;
    return caesar_shift_char(c, eff);
}

extern "C" __declspec(dllexport) int cipher_state_run(CipherState *st, char *buf, int len)
{
    int i;
    if (st == 0 || buf == 0 || len <= 0)
        return 0;
    for (i = 0; i < len; ++i)
        buf[i] = (char)cipher_state_next(st, (unsigned char)buf[i]);
    return len;
}

extern "C" __declspec(dllexport) int64_t mix_fold(const char *buf, int len, int64_t init)
{
    int i;
    int64_t acc = init;
    if (buf == 0)
        return acc;
    for (i = 0; i < len; ++i) {
        int64_t v = (int64_t)(unsigned char)buf[i];
        if ((i & 1) == 0)
            acc += v * 3;
        else
            acc ^= (v << 2);
    }
    return acc;
}

extern "C" __declspec(dllexport) int gcd_step(int a, int b)
{
    if (b == 0)
        return a < 0 ? -a : a;
    return gcd_step(b, a % b);
}
