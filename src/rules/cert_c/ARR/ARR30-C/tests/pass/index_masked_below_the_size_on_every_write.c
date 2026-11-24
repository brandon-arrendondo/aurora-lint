/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every write that reaches the index keeps it under the size
 *
 * `n` starts at 0 and each turn of the loop masks it with 63, so whichever
 * write the read sees, `cache[n]` stays inside `cache[64]`.
 */
#include <stdint.h>

static uint64_t cache[64];

uint64_t combine(uint64_t c, uint64_t len)
{
    unsigned n = 0;
    do {
        if (len & 1)
            c ^= cache[n];
        len >>= 1;
        n = (n + 1) & 63;
    } while (len != 0);
    return c;
}
