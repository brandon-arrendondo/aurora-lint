/*
 * Rule: ERR33-C
 * Status: FAIL - USE(p) expands to a call that consumes p; it tests nothing,
 * so the malloc result is used before the null test.
 */

#include <stdlib.h>

extern void consume(char *);

#define USE(x) consume(x)

void f(void) {
    char *p = malloc(4);
    USE(p);
    if (!p) {
        return;
    }
}
