/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger ARR39-C violation
 *
 * The same sums with the pointer on the right, each correct: an element
 * count added to a typed pointer, or a byte count added to a byte pointer.
 */

#include <stddef.h>
#include <string.h>

struct rec {
    int a;
    long b;
    int c;
};

int *elements_on_the_left(int *p, size_t n)
{
    return n + p;
}

int read_at_index(int *d)
{
    size_t k = 2;
    return *(k + d);
}

void clear_from_member(struct rec *r)
{
    memset(offsetof(struct rec, b) + (unsigned char *)r, 0,
           sizeof(*r) - offsetof(struct rec, b));
}

long sum_by_elements(const long *v)
{
    long total = 0;
    long buf[8];
    for (size_t i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
        total += *(i + v);
    }
    return total;
}

void walk(const unsigned char *start, const unsigned char *cursor)
{
    int buf[16];
    while (cursor < sizeof(buf) + start) {
        cursor++;
    }
    (void)buf;
}
