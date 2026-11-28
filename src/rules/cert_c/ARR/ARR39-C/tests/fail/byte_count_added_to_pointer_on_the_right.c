/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: FAIL - Should trigger ARR39-C violation
 * Expect: count=6
 *
 * A sum takes its pointer on either side: `n * sizeof(int) + p` moves `p`
 * by n * sizeof(int) elements, as `p + n * sizeof(int)` does. So does a
 * byte count reached through a call's argument, a loop counter that runs
 * to a byte count, and a loop bound.
 */

#include <stddef.h>
#include <string.h>

struct rec {
    int a;
    long b;
    int c;
};

int *scaled_on_the_left(int *p, size_t n)
{
    return n * sizeof(int) + p; /* Expect: here */
}

int read_at_offset(int *d)
{
    size_t k = 2 * sizeof(int);
    return *(k + d); /* Expect: here */
}

void clear_from_member(struct rec *r)
{
    memset(offsetof(struct rec, b) + r, 0, sizeof(*r)); /* Expect: here */
}

long sum_by_bytes(const long *v)
{
    long total = 0;
    long buf[8];
    for (size_t i = 0; i < sizeof(buf); i++) { /* Expect: here */
        total += *(i + v);
    }
    return total;
}

void walk(const int *start, const int *cursor)
{
    int buf[16];
    while (cursor < sizeof(buf) + start) { /* Expect: here */
        cursor++;
    }
    (void)buf;
}
