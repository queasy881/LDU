/* string_ops.cpp - C-string processing routines, no libc.
 * Decompiler test target. Compile: cl /LD /Od string_ops.cpp
 * Only <stdint.h> allowed. Pure, deterministic functions.
 */
#include <stdint.h>

/* ----- basic helpers ----- */

extern "C" __declspec(dllexport) int my_strlen(const char *s)
{
    int n = 0;
    if (s == 0)
        return 0;
    while (s[n] != '\0')
        n++;
    return n;
}

extern "C" __declspec(dllexport) int my_strcmp(const char *a, const char *b)
{
    int i = 0;
    if (a == 0 || b == 0)
        return (a == b) ? 0 : (a == 0 ? -1 : 1);
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i])
            return (int)((unsigned char)a[i]) - (int)((unsigned char)b[i]);
        i++;
    }
    return (int)((unsigned char)a[i]) - (int)((unsigned char)b[i]);
}

extern "C" __declspec(dllexport) char *my_strcpy(char *dst, const char *src)
{
    int i = 0;
    if (dst == 0 || src == 0)
        return dst;
    while (src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}

extern "C" __declspec(dllexport) char *my_strcat(char *dst, const char *src)
{
    int d = 0;
    int s = 0;
    if (dst == 0 || src == 0)
        return dst;
    while (dst[d] != '\0')
        d++;
    while (src[s] != '\0') {
        dst[d] = src[s];
        d++;
        s++;
    }
    dst[d] = '\0';
    return dst;
}

extern "C" __declspec(dllexport) const char *my_strchr(const char *s, int c)
{
    int i = 0;
    char target = (char)c;
    if (s == 0)
        return 0;
    for (i = 0;; i++) {
        if (s[i] == target)
            return &s[i];
        if (s[i] == '\0')
            break;
    }
    return 0;
}

extern "C" __declspec(dllexport) const char *my_strrchr(const char *s, int c)
{
    const char *found = 0;
    int i = 0;
    char target = (char)c;
    if (s == 0)
        return 0;
    while (1) {
        if (s[i] == target)
            found = &s[i];
        if (s[i] == '\0')
            break;
        i++;
    }
    return found;
}

extern "C" __declspec(dllexport) int count_char(const char *s, int c)
{
    int count = 0;
    int i = 0;
    char target = (char)c;
    if (s == 0)
        return 0;
    while (s[i] != '\0') {
        if (s[i] == target)
            count++;
        i++;
    }
    return count;
}

/* ----- case conversion ----- */

extern "C" __declspec(dllexport) int to_upper_inplace(char *s)
{
    int changed = 0;
    int i = 0;
    if (s == 0)
        return 0;
    while (s[i] != '\0') {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = (char)(s[i] - ('a' - 'A'));
            changed++;
        }
        i++;
    }
    return changed;
}

extern "C" __declspec(dllexport) int to_lower_inplace(char *s)
{
    int changed = 0;
    int i = 0;
    if (s == 0)
        return 0;
    while (s[i] != '\0') {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = (char)(s[i] + ('a' - 'A'));
            changed++;
        }
        i++;
    }
    return changed;
}

extern "C" __declspec(dllexport) void reverse_str(char *s)
{
    int len = 0;
    int i = 0;
    int j = 0;
    char tmp = 0;
    if (s == 0)
        return;
    while (s[len] != '\0')
        len++;
    i = 0;
    j = len - 1;
    while (i < j) {
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        i++;
        j--;
    }
}

extern "C" __declspec(dllexport) int is_palindrome(const char *s)
{
    int len = 0;
    int i = 0;
    int j = 0;
    if (s == 0)
        return 0;
    while (s[len] != '\0')
        len++;
    i = 0;
    j = len - 1;
    while (i < j) {
        if (s[i] != s[j])
            return 0;
        i++;
        j--;
    }
    return 1;
}

/* ----- numeric conversion ----- */

extern "C" __declspec(dllexport) int my_atoi(const char *s)
{
    int i = 0;
    int sign = 1;
    int value = 0;
    if (s == 0)
        return 0;
    while (s[i] == ' ' || s[i] == '\t')
        i++;
    if (s[i] == '-') {
        sign = -1;
        i++;
    } else if (s[i] == '+') {
        i++;
    }
    while (s[i] >= '0' && s[i] <= '9') {
        value = value * 10 + (s[i] - '0');
        i++;
    }
    return value * sign;
}

extern "C" __declspec(dllexport) int my_itoa(int value, char *buf)
{
    char tmp[16];
    int n = 0;
    int len = 0;
    int i = 0;
    unsigned int u = 0;
    int neg = 0;
    if (buf == 0)
        return 0;
    if (value < 0) {
        neg = 1;
        u = (unsigned int)(-(value + 1)) + 1u;
    } else {
        u = (unsigned int)value;
    }
    do {
        tmp[n] = (char)('0' + (u % 10u));
        n++;
        u /= 10u;
    } while (u != 0 && n < 15);
    if (neg) {
        buf[len] = '-';
        len++;
    }
    for (i = n - 1; i >= 0; i--) {
        buf[len] = tmp[i];
        len++;
    }
    buf[len] = '\0';
    return len;
}

/* ----- prefix / suffix ----- */

extern "C" __declspec(dllexport) int starts_with(const char *s, const char *prefix)
{
    int i = 0;
    if (s == 0 || prefix == 0)
        return 0;
    while (prefix[i] != '\0') {
        if (s[i] != prefix[i])
            return 0;
        i++;
    }
    return 1;
}

extern "C" __declspec(dllexport) int ends_with(const char *s, const char *suffix)
{
    int sl = 0;
    int fl = 0;
    int i = 0;
    if (s == 0 || suffix == 0)
        return 0;
    while (s[sl] != '\0')
        sl++;
    while (suffix[fl] != '\0')
        fl++;
    if (fl > sl)
        return 0;
    for (i = 0; i < fl; i++) {
        if (s[sl - fl + i] != suffix[i])
            return 0;
    }
    return 1;
}

/* ----- counting / classification ----- */

extern "C" __declspec(dllexport) int count_vowels(const char *s)
{
    int count = 0;
    int i = 0;
    char c = 0;
    if (s == 0)
        return 0;
    while (s[i] != '\0') {
        c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + ('a' - 'A'));
        switch (c) {
        case 'a':
        case 'e':
        case 'i':
        case 'o':
        case 'u':
            count++;
            break;
        default:
            break;
        }
        i++;
    }
    return count;
}

extern "C" __declspec(dllexport) int count_words(const char *s)
{
    int count = 0;
    int in_word = 0;
    int i = 0;
    char c = 0;
    if (s == 0)
        return 0;
    while (s[i] != '\0') {
        c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            in_word = 0;
        } else {
            if (in_word == 0) {
                count++;
                in_word = 1;
            }
        }
        i++;
    }
    return count;
}

extern "C" __declspec(dllexport) int char_at_safe(const char *s, int index)
{
    int len = 0;
    if (s == 0 || index < 0)
        return -1;
    while (s[len] != '\0')
        len++;
    if (index >= len)
        return -1;
    return (int)((unsigned char)s[index]);
}

extern "C" __declspec(dllexport) int last_index_of(const char *s, int c)
{
    int last = -1;
    int i = 0;
    char target = (char)c;
    if (s == 0)
        return -1;
    while (s[i] != '\0') {
        if (s[i] == target)
            last = i;
        i++;
    }
    return last;
}

/* ----- hashing ----- */

extern "C" __declspec(dllexport) uint32_t str_hash_djb2(const char *s)
{
    uint32_t hash = 5381u;
    int i = 0;
    if (s == 0)
        return 0u;
    while (s[i] != '\0') {
        hash = ((hash << 5) + hash) + (uint32_t)((unsigned char)s[i]);
        i++;
    }
    return hash;
}

extern "C" __declspec(dllexport) int is_digit_str(const char *s)
{
    int i = 0;
    if (s == 0)
        return 0;
    if (s[0] == '\0')
        return 0;
    while (s[i] != '\0') {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        i++;
    }
    return 1;
}

extern "C" __declspec(dllexport) int skip_spaces(const char *s)
{
    int i = 0;
    if (s == 0)
        return 0;
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')
        i++;
    return i;
}

extern "C" __declspec(dllexport) int copy_n(char *dst, const char *src, int n)
{
    int i = 0;
    if (dst == 0 || src == 0 || n <= 0)
        return 0;
    while (i < n && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    if (i < n)
        dst[i] = '\0';
    return i;
}

extern "C" __declspec(dllexport) int equal_n(const char *a, const char *b, int n)
{
    int i = 0;
    if (a == 0 || b == 0)
        return 0;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i])
            return 0;
        if (a[i] == '\0')
            return 1;
    }
    return 1;
}

/* ----- extra utility: index of substring (brute force) ----- */

extern "C" __declspec(dllexport) int index_of_substr(const char *hay, const char *needle)
{
    int hl = 0;
    int nl = 0;
    int i = 0;
    int j = 0;
    if (hay == 0 || needle == 0)
        return -1;
    while (hay[hl] != '\0')
        hl++;
    while (needle[nl] != '\0')
        nl++;
    if (nl == 0)
        return 0;
    if (nl > hl)
        return -1;
    for (i = 0; i <= hl - nl; i++) {
        j = 0;
        while (j < nl && hay[i + j] == needle[j])
            j++;
        if (j == nl)
            return i;
    }
    return -1;
}

extern "C" __declspec(dllexport) int trim_trailing(char *s)
{
    int len = 0;
    int removed = 0;
    if (s == 0)
        return 0;
    while (s[len] != '\0')
        len++;
    while (len > 0) {
        char c = s[len - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            s[len - 1] = '\0';
            len--;
            removed++;
        } else {
            break;
        }
    }
    return removed;
}
