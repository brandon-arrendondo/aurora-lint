/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A guard on the path, or a mask, keeps each value inside its target
 *
 * Each conversion is reached only where the value fits the target: inside
 * a guard against the target's own limits, past an early return that
 * rejects the rest, or through a mask no wider than the target. The guard
 * is read with its polarity, and nothing writes the value between the
 * guard and the conversion.
 */

#include <limits.h>
#include <stdint.h>

void sink(int);

void inside_guard(int v)
{
    if (v >= 0 && v <= UCHAR_MAX) {
        unsigned char c = (unsigned char)v;
        sink(c);
    }
}

void past_early_return(long v)
{
    if (v < SCHAR_MIN || v > SCHAR_MAX)
        return;
    signed char c = (signed char)v;
    sink(c);
}

void masked(int v, int n)
{
    unsigned char low = (unsigned char)(v & 0xFF);
    uint8_t bounded = (n & 0x7F) + 1;
    sink(low + bounded);
}
