/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro defined after the call does not expand it; the call is the project function of that name, which can read the static
 */

#include <stdlib.h>

static char *cache;

static void report(void) {
    if (cache != NULL) {
        cache[0] = 'x';
    }
}

void flush(void) {
    free(cache);
    report();
    cache = NULL;
}

#define report() ((void)0)
