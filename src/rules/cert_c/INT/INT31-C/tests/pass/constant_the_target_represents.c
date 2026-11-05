/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A constant the target holds, or one of CERT's exceptions, keeps its value
 *
 * Each constant fits the type it is stored in or cast to. A negative
 * constant into an unsigned type at least as wide as `int` is CERT's EX3,
 * a character constant into a character type is EX2, and a store into
 * `_Bool` is a truth value.
 */

#include <stdint.h>
#include <stdbool.h>

#define SMALL 200

void sink(unsigned long);
void sink_char(int);

void stores(void)
{
    uint8_t b = 255;
    uint8_t b2 = SMALL;
    unsigned u = -1;
    unsigned long ul = -1;
    char c = 'a';
    signed char sc = -128;
    bool flag = 2;
    sink(b + b2 + u + ul + flag + (uint8_t)7 + (size_t)-1);
    sink_char(c);
    sink_char(sc);
}
