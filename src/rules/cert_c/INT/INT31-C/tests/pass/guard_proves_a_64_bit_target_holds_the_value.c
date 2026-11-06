/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A non-negative guard proves a 64-bit unsigned target holds the value
 * Settings: data_model=lp64
 *
 * A signed `long` known not to be negative fits `uint64_t`, whether the
 * guard is an earlier operand of `&&` or a test on the path. The largest
 * `uint64_t` lies past `long`, which does not make the guard prove less.
 */

typedef unsigned long uint64_t;

struct header {
    uint64_t len;
    uint64_t alloc;
};

int room_for(const struct header *h, long incr)
{
    return incr >= 0 && h->alloc - h->len >= (uint64_t)incr;
}

uint64_t as_length(long n)
{
    if (n < 0) {
        return 0;
    }
    return (uint64_t)n;
}
