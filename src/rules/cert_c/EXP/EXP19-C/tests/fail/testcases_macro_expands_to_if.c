/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: FAIL - a macro that expands to an if statement, not a braced
 * block, leaves the for body unbraced
 */

#include <stddef.h>

void swapfunc(char *a, char *b, size_t n, int swaptype);

#define swap(a, b)                                      \
    if (swaptype == 0) {                                \
        long t = *(long *)(void *)(a);                  \
        *(long *)(void *)(a) = *(long *)(void *)(b);    \
        *(long *)(void *)(b) = t;                       \
    } else                                              \
        swapfunc(a, b, es, swaptype)

void sort(char *a, size_t n, size_t es, int swaptype) {
    char *pl;
    for (pl = a + es; pl < a + n * es; pl += es)
        swap(pl, pl - es);
}
