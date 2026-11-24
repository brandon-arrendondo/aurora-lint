/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A write that reaches the index may leave it past the size
 * Expect: count=2
 *
 * In `wide_mask` the mask lets `n` reach 127 in `cache[64]`. In
 * `through_a_pointer` the mask is in range, but `*q = 99` writes `n`
 * through its address, which no list of writes to `n` holds.
 */
#include <stdint.h>

static uint64_t cache[64];
extern int more(void);

uint64_t wide_mask(uint64_t c)
{
    unsigned n = 0;
    do {
        c ^= cache[n]; /* Expect: here */
        n = (n + 1) & 127;
    } while (more());
    return c;
}

uint64_t through_a_pointer(uint64_t c)
{
    unsigned n = 0;
    unsigned *q = &n;
    do {
        c ^= cache[n]; /* Expect: here */
        n = (n + 1) & 63;
        *q = 99;
    } while (more());
    return c;
}
