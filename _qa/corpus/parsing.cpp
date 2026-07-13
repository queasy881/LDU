/* parsing.cpp - char parsing behavioral-test target for decompiler QA.
 * Compile: cl /LD /Od /W3 parsing.cpp
 * Pure deterministic C-style functions operating on const char* input.
 */
#include <stdint.h>

/* ---- structures ---------------------------------------------------------- */

typedef struct ParseState {
    const char *buf;
    int len;
    int pos;
    int error;
} ParseState;

typedef struct NumberInfo {
    int valid;
    int negative;
    int has_fraction;
    int digit_count;
    int64_t int_part;
} NumberInfo;

typedef struct TokenSpan {
    int start;
    int length;
} TokenSpan;

/* ---- character classifiers ----------------------------------------------- */

extern "C" __declspec(dllexport) int is_space(int c)
{
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) int is_digit(int c)
{
    if (c >= '0' && c <= '9') {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) int is_alpha(int c)
{
    if (c >= 'a' && c <= 'z') {
        return 1;
    }
    if (c >= 'A' && c <= 'Z') {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) int is_alnum(int c)
{
    if (is_alpha(c) != 0) {
        return 1;
    }
    return is_digit(c);
}

extern "C" __declspec(dllexport) int is_hex_digit(int c)
{
    if (is_digit(c) != 0) {
        return 1;
    }
    if (c >= 'a' && c <= 'f') {
        return 1;
    }
    if (c >= 'A' && c <= 'F') {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) int is_ident_start(int c)
{
    if (is_alpha(c) != 0) {
        return 1;
    }
    if (c == '_') {
        return 1;
    }
    return 0;
}

extern "C" __declspec(dllexport) int is_ident_char(int c)
{
    if (is_ident_start(c) != 0) {
        return 1;
    }
    return is_digit(c);
}

extern "C" __declspec(dllexport) int to_lower(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

extern "C" __declspec(dllexport) int to_upper(int c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 32;
    }
    return c;
}

/* ---- digit conversion ---------------------------------------------------- */

extern "C" __declspec(dllexport) int char_to_digit(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return -1;
}

extern "C" __declspec(dllexport) int hex_char_to_value(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* ---- length helper ------------------------------------------------------- */

extern "C" __declspec(dllexport) int str_length(const char *s)
{
    int n = 0;
    if (s == 0) {
        return 0;
    }
    while (s[n] != '\0') {
        n = n + 1;
        if (n >= 65536) {
            break;
        }
    }
    return n;
}

/* ---- whitespace skipping ------------------------------------------------- */

extern "C" __declspec(dllexport) int skip_ws(const char *s, int from)
{
    int i;
    if (s == 0) {
        return from;
    }
    if (from < 0) {
        from = 0;
    }
    i = from;
    while (s[i] != '\0') {
        if (is_space((int)(unsigned char)s[i]) == 0) {
            break;
        }
        i = i + 1;
    }
    return i;
}

extern "C" __declspec(dllexport) int skip_to_ws(const char *s, int from)
{
    int i;
    if (s == 0) {
        return from;
    }
    if (from < 0) {
        from = 0;
    }
    i = from;
    while (s[i] != '\0') {
        if (is_space((int)(unsigned char)s[i]) != 0) {
            break;
        }
        i = i + 1;
    }
    return i;
}

/* ---- integer parsing ----------------------------------------------------- */

extern "C" __declspec(dllexport) int64_t parse_int(const char *s, int *consumed)
{
    int i = 0;
    int sign = 1;
    int64_t value = 0;
    int seen = 0;

    if (s == 0) {
        if (consumed != 0) {
            *consumed = 0;
        }
        return 0;
    }
    i = skip_ws(s, 0);
    if (s[i] == '+') {
        i = i + 1;
    } else if (s[i] == '-') {
        sign = -1;
        i = i + 1;
    }
    while (s[i] != '\0') {
        int d = char_to_digit((int)(unsigned char)s[i]);
        if (d < 0) {
            break;
        }
        value = value * 10 + d;
        seen = seen + 1;
        i = i + 1;
    }
    if (consumed != 0) {
        *consumed = seen;
    }
    if (seen == 0) {
        return 0;
    }
    return value * sign;
}

extern "C" __declspec(dllexport) uint32_t parse_hex(const char *s, int *ok)
{
    int i = 0;
    uint32_t value = 0;
    int seen = 0;

    if (s == 0) {
        if (ok != 0) {
            *ok = 0;
        }
        return 0;
    }
    i = skip_ws(s, 0);
    if (s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        i = i + 2;
    }
    while (s[i] != '\0') {
        int v = hex_char_to_value((int)(unsigned char)s[i]);
        if (v < 0) {
            break;
        }
        value = (value << 4) | (uint32_t)v;
        seen = seen + 1;
        i = i + 1;
    }
    if (ok != 0) {
        *ok = (seen > 0) ? 1 : 0;
    }
    return value;
}

extern "C" __declspec(dllexport) int parse_binary(const char *s)
{
    int i = 0;
    int value = 0;
    int seen = 0;
    if (s == 0) {
        return -1;
    }
    do {
        char c = s[i];
        if (c == '0' || c == '1') {
            value = (value << 1) | (c - '0');
            seen = seen + 1;
            i = i + 1;
        } else {
            break;
        }
    } while (s[i] != '\0');
    if (seen == 0) {
        return -1;
    }
    return value;
}

/* ---- boolean parsing ----------------------------------------------------- */

extern "C" __declspec(dllexport) int parse_bool(const char *s, int *out)
{
    int i;
    if (s == 0 || out == 0) {
        return 0;
    }
    i = skip_ws(s, 0);
    switch (to_lower((int)(unsigned char)s[i])) {
        case 't':
            if (to_lower((int)(unsigned char)s[i + 1]) == 'r') {
                *out = 1;
                return 1;
            }
            break;
        case 'f':
            if (to_lower((int)(unsigned char)s[i + 1]) == 'a') {
                *out = 0;
                return 1;
            }
            break;
        case 'y':
            *out = 1;
            return 1;
        case 'n':
            *out = 0;
            return 1;
        case '1':
            *out = 1;
            return 1;
        case '0':
            *out = 0;
            return 1;
        default:
            break;
    }
    return 0;
}

/* ---- tokenization -------------------------------------------------------- */

extern "C" __declspec(dllexport) int next_token_len(const char *s, int from)
{
    int start;
    int end;
    if (s == 0) {
        return 0;
    }
    if (from < 0) {
        from = 0;
    }
    start = skip_ws(s, from);
    end = skip_to_ws(s, start);
    return end - start;
}

extern "C" __declspec(dllexport) int count_tokens(const char *s)
{
    int i = 0;
    int count = 0;
    if (s == 0) {
        return 0;
    }
    while (s[i] != '\0') {
        i = skip_ws(s, i);
        if (s[i] == '\0') {
            break;
        }
        count = count + 1;
        i = skip_to_ws(s, i);
    }
    return count;
}

extern "C" __declspec(dllexport) int find_token(const char *s, int index, TokenSpan *span)
{
    int i = 0;
    int n = 0;
    if (s == 0 || span == 0 || index < 0) {
        return 0;
    }
    while (s[i] != '\0') {
        int start = skip_ws(s, i);
        int end;
        if (s[start] == '\0') {
            break;
        }
        end = skip_to_ws(s, start);
        if (n == index) {
            span->start = start;
            span->length = end - start;
            return 1;
        }
        n = n + 1;
        i = end;
    }
    return 0;
}

extern "C" __declspec(dllexport) int ident_length(const char *s, int from)
{
    int i;
    if (s == 0) {
        return 0;
    }
    if (from < 0) {
        from = 0;
    }
    i = from;
    if (is_ident_start((int)(unsigned char)s[i]) == 0) {
        return 0;
    }
    i = i + 1;
    while (s[i] != '\0' && is_ident_char((int)(unsigned char)s[i]) != 0) {
        i = i + 1;
    }
    return i - from;
}

/* ---- number validation --------------------------------------------------- */

extern "C" __declspec(dllexport) int validate_number(const char *s, NumberInfo *info)
{
    int i = 0;
    int digits = 0;
    int frac_digits = 0;
    int has_dot = 0;
    int64_t whole = 0;

    if (info != 0) {
        info->valid = 0;
        info->negative = 0;
        info->has_fraction = 0;
        info->digit_count = 0;
        info->int_part = 0;
    }
    if (s == 0) {
        return 0;
    }
    i = skip_ws(s, 0);
    if (s[i] == '+' || s[i] == '-') {
        if (info != 0 && s[i] == '-') {
            info->negative = 1;
        }
        i = i + 1;
    }
    while (s[i] != '\0') {
        char c = s[i];
        if (is_digit((int)(unsigned char)c) != 0) {
            if (has_dot == 0) {
                whole = whole * 10 + (c - '0');
                digits = digits + 1;
            } else {
                frac_digits = frac_digits + 1;
            }
            i = i + 1;
        } else if (c == '.' && has_dot == 0) {
            has_dot = 1;
            i = i + 1;
        } else {
            break;
        }
    }
    i = skip_ws(s, i);
    if (s[i] != '\0') {
        return 0;
    }
    if (digits == 0 && frac_digits == 0) {
        return 0;
    }
    if (info != 0) {
        info->valid = 1;
        info->has_fraction = (has_dot != 0 && frac_digits > 0) ? 1 : 0;
        info->digit_count = digits + frac_digits;
        info->int_part = whole;
    }
    return 1;
}

extern "C" __declspec(dllexport) int is_valid_ident(const char *s)
{
    int i = 0;
    int len;
    if (s == 0) {
        return 0;
    }
    len = ident_length(s, 0);
    if (len == 0) {
        return 0;
    }
    i = len;
    while (s[i] != '\0') {
        if (is_space((int)(unsigned char)s[i]) == 0) {
            return 0;
        }
        i = i + 1;
    }
    return 1;
}

/* ---- recursion ----------------------------------------------------------- */

extern "C" __declspec(dllexport) int64_t digit_sum(int64_t n)
{
    int64_t v;
    if (n < 0) {
        n = -n;
    }
    if (n < 10) {
        return n;
    }
    v = n % 10;
    return v + digit_sum(n / 10);
}

extern "C" __declspec(dllexport) int count_digit_runs(const char *s)
{
    int i = 0;
    int runs = 0;
    int in_run = 0;
    if (s == 0) {
        return 0;
    }
    for (i = 0; s[i] != '\0'; i = i + 1) {
        if (is_digit((int)(unsigned char)s[i]) != 0) {
            if (in_run == 0) {
                runs = runs + 1;
                in_run = 1;
            }
        } else {
            in_run = 0;
        }
    }
    return runs;
}

/* ---- expression evaluation ----------------------------------------------- */

extern "C" __declspec(dllexport) int64_t simple_eval_addsub(const char *s, int *ok)
{
    int i = 0;
    int64_t acc = 0;
    int op = 1; /* 1 = add, -1 = subtract */
    int expect_num = 1;
    int any = 0;

    if (s == 0) {
        if (ok != 0) {
            *ok = 0;
        }
        return 0;
    }
    while (s[i] != '\0') {
        i = skip_ws(s, i);
        if (s[i] == '\0') {
            break;
        }
        if (expect_num != 0) {
            int consumed = 0;
            int sign = 1;
            int64_t term = 0;
            if (s[i] == '+') {
                i = i + 1;
            } else if (s[i] == '-') {
                sign = -1;
                i = i + 1;
            }
            i = skip_ws(s, i);
            while (is_digit((int)(unsigned char)s[i]) != 0) {
                term = term * 10 + (s[i] - '0');
                consumed = consumed + 1;
                i = i + 1;
            }
            if (consumed == 0) {
                if (ok != 0) {
                    *ok = 0;
                }
                return 0;
            }
            acc = acc + op * sign * term;
            expect_num = 0;
            any = 1;
        } else {
            char c = s[i];
            if (c == '+') {
                op = 1;
            } else if (c == '-') {
                op = -1;
            } else {
                if (ok != 0) {
                    *ok = 0;
                }
                return 0;
            }
            i = i + 1;
            expect_num = 1;
        }
    }
    if (expect_num != 0 && any != 0) {
        if (ok != 0) {
            *ok = 0;
        }
        return 0;
    }
    if (ok != 0) {
        *ok = any;
    }
    return acc;
}

/* ---- ParseState driven helpers ------------------------------------------- */

extern "C" __declspec(dllexport) void state_init(ParseState *st, const char *buf, int len)
{
    if (st == 0) {
        return;
    }
    st->buf = buf;
    st->len = (buf != 0 && len >= 0) ? len : 0;
    st->pos = 0;
    st->error = 0;
}

extern "C" __declspec(dllexport) int state_peek(const ParseState *st)
{
    if (st == 0 || st->buf == 0) {
        return -1;
    }
    if (st->pos < 0 || st->pos >= st->len) {
        return -1;
    }
    return (int)(unsigned char)st->buf[st->pos];
}

extern "C" __declspec(dllexport) int state_advance(ParseState *st)
{
    int c;
    if (st == 0 || st->buf == 0) {
        return -1;
    }
    if (st->pos >= st->len) {
        st->error = 1;
        return -1;
    }
    c = (int)(unsigned char)st->buf[st->pos];
    st->pos = st->pos + 1;
    return c;
}

extern "C" __declspec(dllexport) int state_match_digits(ParseState *st)
{
    int count = 0;
    if (st == 0 || st->buf == 0) {
        return 0;
    }
    while (st->pos < st->len) {
        if (is_digit((int)(unsigned char)st->buf[st->pos]) == 0) {
            break;
        }
        st->pos = st->pos + 1;
        count = count + 1;
    }
    return count;
}

extern "C" __declspec(dllexport) int checksum_tokens(const char *s)
{
    int i = 0;
    int sum = 0;
    int len;
    if (s == 0) {
        return 0;
    }
    len = count_tokens(s);
    for (i = 0; i < len; i = i + 1) {
        TokenSpan span;
        if (find_token(s, i, &span) != 0) {
            int j;
            for (j = 0; j < span.length; j = j + 1) {
                sum = sum + (int)(unsigned char)s[span.start + j];
            }
        }
    }
    return sum;
}
