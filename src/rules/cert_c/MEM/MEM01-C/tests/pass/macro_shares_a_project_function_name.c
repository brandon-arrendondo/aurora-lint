/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - a call spelled as a function-like macro expands in place; it is not the project function of that name
 */

#include <stdlib.h>

static char *cache;

static void report(void) {
    if (cache != NULL) {
        cache[0] = 'x';
    }
}

#define report() ((void)0)

void flush(void) {
    free(cache);
    report();
    cache = NULL;
}
