/*
 * Rule: EXP34-C
 * Source: wiki, CERT EXP34-C exception EX1
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * C11 6.5.3.2p3: in `&*p` neither operator is evaluated, and `&p[i]` is
 * `p + i` with no `*` evaluated. Neither dereferences `p`, even though
 * malloc() may have returned NULL.
 */
#include <stdlib.h>

int *first(size_t n) {
    int *p = malloc(n * sizeof *p);
    int *q = &*p;
    return q;
}

int *third(size_t n) {
    int *p = malloc(n * sizeof *p);
    return &(p[2]);
}
