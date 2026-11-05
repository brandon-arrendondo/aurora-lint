/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A guard that keeps the value out of the target, or arithmetic past it, does not make the conversion safe
 * Expect: count=5
 *
 * The first cast runs only where `v` is ABOVE `UCHAR_MAX`, so the guard
 * proves the conversion loses data rather than that it is safe; it both
 * narrows and changes the sign, two findings. The
 * stores convert arithmetic whose promoted type is `int` into narrower
 * types, and nothing bounds the operands.
 */

#include <limits.h>
#include <stdint.h>

void sink(int);

void wrong_polarity(int v)
{
    if (v > UCHAR_MAX) {
        unsigned char c = 0;
        c = (unsigned char)v; /* Expect: here */
        sink(c);
    }
}

void arithmetic(uint8_t a, uint8_t b, int n)
{
    uint8_t sum = a + b;   /* Expect: here */
    uint8_t next = n + 1;  /* Expect: here */
    short product = a * b; /* Expect: here */
    sink(sum + next + product);
}
