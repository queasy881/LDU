// control_flow.cpp
// Theme: heavy branching, switch statements, state machines.
// Decompiler test target. C-style C++ only. Built with: cl /LD /Od
#include <stdint.h>

// ---------------------------------------------------------------------------
// classify_char: switch over character ranges.
// 0=control,1=digit,2=upper,3=lower,4=space,5=punct,6=other
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int classify_char(int c)
{
    if (c < 0 || c > 255)
        return 6;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        return 4;
    if (c < 32 || c == 127)
        return 0;
    if (c >= '0' && c <= '9')
        return 1;
    if (c >= 'A' && c <= 'Z')
        return 2;
    if (c >= 'a' && c <= 'z')
        return 3;
    switch (c)
    {
        case '!': case '?': case '.': case ',': case ';': case ':':
            return 5;
        default:
            return 6;
    }
}

// ---------------------------------------------------------------------------
// calc: integer ALU dispatched by op code.
// op: 0=add 1=sub 2=mul 3=div 4=mod 5=and 6=or 7=xor 8=shl 9=shr
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int calc(int a, int b, int op)
{
    int result = 0;
    switch (op)
    {
        case 0: result = a + b; break;
        case 1: result = a - b; break;
        case 2: result = a * b; break;
        case 3:
            if (b == 0)
                result = 0;
            else
                result = a / b;
            break;
        case 4:
            if (b == 0)
                result = 0;
            else
                result = a % b;
            break;
        case 5: result = a & b; break;
        case 6: result = a | b; break;
        case 7: result = a ^ b; break;
        case 8: result = a << (b & 31); break;
        case 9: result = a >> (b & 31); break;
        default: result = 0; break;
    }
    return result;
}

// ---------------------------------------------------------------------------
// letter_grade: percentage to grade bucket (0=A,1=B,2=C,3=D,4=F).
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int letter_grade(int pct)
{
    if (pct < 0)
        pct = 0;
    else if (pct > 100)
        pct = 100;

    if (pct >= 90)
        return 0;
    else if (pct >= 80)
        return 1;
    else if (pct >= 70)
        return 2;
    else if (pct >= 60)
        return 3;
    return 4;
}

// ---------------------------------------------------------------------------
// day_name_len: length of weekday name (0=Sunday..6=Saturday).
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int day_name_len(int day)
{
    switch (day)
    {
        case 0: return 6;  // Sunday
        case 1: return 6;  // Monday
        case 2: return 7;  // Tuesday
        case 3: return 9;  // Wednesday
        case 4: return 8;  // Thursday
        case 5: return 6;  // Friday
        case 6: return 8;  // Saturday
        default: return -1;
    }
}

// ---------------------------------------------------------------------------
// fsm_run: small state machine driven by a stream of int tokens.
// Tokens: 0=tick 1=reset 2=fault 3=clear. Returns final state.
// States: 0=idle 1=run 2=halt 3=error
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int fsm_run(const int* tokens, int n)
{
    int state = 0;
    int i = 0;
    if (tokens == 0)
        return -1;
    while (i < n)
    {
        int t = tokens[i];
        switch (state)
        {
            case 0: // idle
                if (t == 0) state = 1;
                else if (t == 2) state = 3;
                break;
            case 1: // run
                if (t == 1) state = 0;
                else if (t == 2) state = 3;
                else if (t == 0) state = 1;
                else state = 2;
                break;
            case 2: // halt
                if (t == 1) state = 0;
                else if (t == 3) state = 1;
                break;
            case 3: // error
                if (t == 3) state = 0;
                break;
            default:
                state = 0;
                break;
        }
        i++;
    }
    return state;
}

// ---------------------------------------------------------------------------
// traffic_next: traffic light next state. 0=green 1=yellow 2=red.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int traffic_next(int cur)
{
    switch (cur)
    {
        case 0: return 1;  // green -> yellow
        case 1: return 2;  // yellow -> red
        case 2: return 0;  // red -> green
        default: return 2; // fail safe to red
    }
}

// ---------------------------------------------------------------------------
// month_days: days in a month for a given year.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int month_days(int month, int year)
{
    switch (month)
    {
        case 1: case 3: case 5: case 7:
        case 8: case 10: case 12:
            return 31;
        case 4: case 6: case 9: case 11:
            return 30;
        case 2:
            if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
                return 29;
            return 28;
        default:
            return 0;
    }
}

// ---------------------------------------------------------------------------
// triangle_type: 0=invalid 1=equilateral 2=isosceles 3=scalene.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int triangle_type(int a, int b, int c)
{
    if (a <= 0 || b <= 0 || c <= 0)
        return 0;
    if (a + b <= c || a + c <= b || b + c <= a)
        return 0;
    if (a == b && b == c)
        return 1;
    if (a == b || b == c || a == c)
        return 2;
    return 3;
}

// ---------------------------------------------------------------------------
// leap_year: 1 if leap, 0 otherwise.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int leap_year(int year)
{
    if (year % 400 == 0)
        return 1;
    if (year % 100 == 0)
        return 0;
    if (year % 4 == 0)
        return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// fizzbuzz_value: 0=number 1=fizz 2=buzz 3=fizzbuzz.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int fizzbuzz_value(int n)
{
    int by3 = (n % 3 == 0);
    int by5 = (n % 5 == 0);
    if (by3 && by5)
        return 3;
    else if (by3)
        return 1;
    else if (by5)
        return 2;
    return 0;
}

// ---------------------------------------------------------------------------
// sign_bucket: -1 negative, 0 zero, 1 positive.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int sign_bucket(int64_t v)
{
    if (v < 0)
        return -1;
    else if (v > 0)
        return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// clamp_to_range: clamp v into [lo, hi], swapping bounds if reversed.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int clamp_to_range(int v, int lo, int hi)
{
    if (lo > hi)
    {
        int tmp = lo;
        lo = hi;
        hi = tmp;
    }
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

// ---------------------------------------------------------------------------
// count_transitions: count adjacent value changes in an int stream.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int count_transitions(const int* data, int n)
{
    int count = 0;
    int i;
    if (data == 0 || n < 2)
        return 0;
    for (i = 1; i < n; i++)
    {
        if (data[i] != data[i - 1])
            count++;
    }
    return count;
}

// ---------------------------------------------------------------------------
// matrix_trace: sum the main diagonal of a row-major square matrix.
// Uses a nested loop to exercise control flow.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int64_t matrix_trace(const int* m, int dim)
{
    int64_t sum = 0;
    int r, col;
    if (m == 0 || dim <= 0)
        return 0;
    for (r = 0; r < dim; r++)
    {
        for (col = 0; col < dim; col++)
        {
            if (r == col)
            {
                sum += (int64_t)m[r * dim + col];
                break;
            }
        }
    }
    return sum;
}

// ---------------------------------------------------------------------------
// gcd_switchy: greatest common divisor, classic Euclid loop.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int gcd_switchy(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0)
    {
        int t = b;
        b = a % b;
        a = t;
    }
    switch (a)
    {
        case 0: return 1; // define gcd(0,0)=1 for this target
        default: return a;
    }
}

// ---------------------------------------------------------------------------
// season_of_month: 0=winter 1=spring 2=summer 3=autumn.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int season_of_month(int month)
{
    switch (month)
    {
        case 12: case 1: case 2:
            return 0;
        case 3: case 4: case 5:
            return 1;
        case 6: case 7: case 8:
            return 2;
        case 9: case 10: case 11:
            return 3;
        default:
            return -1;
    }
}

// ---------------------------------------------------------------------------
// score_to_stars: map a 0..100 score to 0..5 stars via do-while bucketing.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int score_to_stars(int score)
{
    int stars = 0;
    int threshold = 20;
    if (score < 0)
        return 0;
    if (score > 100)
        score = 100;
    do
    {
        if (score >= threshold)
            stars++;
        threshold += 20;
    } while (threshold <= 100);
    return stars;
}

// ---------------------------------------------------------------------------
// parity_word: returns word index 0=even 1=odd for popcount parity.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int parity_word(uint32_t x)
{
    int bits = 0;
    while (x != 0)
    {
        bits += (int)(x & 1u);
        x >>= 1;
    }
    if ((bits & 1) == 0)
        return 0;
    return 1;
}

// ---------------------------------------------------------------------------
// range_sum_skip: sum [lo,hi) skipping multiples of skip; continue/break.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int64_t range_sum_skip(int lo, int hi, int skip)
{
    int64_t sum = 0;
    int i;
    if (skip == 0)
        skip = 1;
    for (i = lo; i < hi; i++)
    {
        if (i % skip == 0)
            continue;
        if (sum > 1000000000)
            break;
        sum += i;
    }
    return sum;
}

// ---------------------------------------------------------------------------
// vowel_count: count vowels in a small fixed scan of a buffer.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int vowel_count(const int* chars, int n)
{
    int count = 0;
    int i;
    if (chars == 0)
        return 0;
    for (i = 0; i < n; i++)
    {
        int ch = chars[i];
        switch (ch)
        {
            case 'a': case 'e': case 'i': case 'o': case 'u':
            case 'A': case 'E': case 'I': case 'O': case 'U':
                count++;
                break;
            default:
                break;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// quadrant_of: which quadrant a point sits in. 0=origin/axes, 1..4 quadrants.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int quadrant_of(int x, int y)
{
    if (x == 0 || y == 0)
        return 0;
    if (x > 0 && y > 0)
        return 1;
    if (x < 0 && y > 0)
        return 2;
    if (x < 0 && y < 0)
        return 3;
    return 4;
}

// ---------------------------------------------------------------------------
// run_length_max: longest run of equal adjacent values.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) int run_length_max(const int* data, int n)
{
    int best = 0;
    int cur = 0;
    int i;
    if (data == 0 || n <= 0)
        return 0;
    cur = 1;
    best = 1;
    for (i = 1; i < n; i++)
    {
        if (data[i] == data[i - 1])
            cur++;
        else
            cur = 1;
        if (cur > best)
            best = cur;
    }
    return best;
}
