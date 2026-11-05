/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A constant the target type cannot represent changes its value
 * Expect: count=6
 *
 * Each store or cast converts a constant to a type too narrow to hold it,
 * so the value the code wrote is not the value it gets: a literal, a macro,
 * an explicit cast, and a negative constant into an unsigned type narrower
 * than `int`, which CERT's exception for negative constants does not
 * cover.
 */

#include <stdint.h>

#define BIG 300

void sink(int);

void stores(void)
{
    uint8_t b = 300;            /* Expect: here */
    uint8_t b2 = BIG;           /* Expect: here */
    unsigned short s = 70000;   /* Expect: here */
    signed char c = 200;        /* Expect: here */
    unsigned char m = -1;       /* Expect: here */
    sink(b + b2 + s + c + m + (uint8_t)300); /* Expect: here */
}
