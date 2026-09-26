/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - a function-like macro whose expansion is a compound
 * statement { ... } gives the if/else a braced body
 */

#include <stddef.h>

#define swapcode(TYPE, parmi, parmj, n) {       \
    size_t i = (n) / sizeof (TYPE);             \
    TYPE *pi = (TYPE *)(void *)(parmi);         \
    TYPE *pj = (TYPE *)(void *)(parmj);         \
    do {                                        \
        TYPE t = *pi;                           \
        *pi++ = *pj;                            \
        *pj++ = t;                              \
    } while (--i > 0);                          \
}

static void swapfunc(char *a, char *b, size_t n, int swaptype) {
    if (swaptype <= 1)
        swapcode(long, a, b, n)
    else
        swapcode(char, a, b, n)
}
