/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - a function-pointer parameter is called, not the project function that shares its name
 */

#include <stdlib.h>

static char *cache;

static void report(void) {
    if (cache != NULL) {
        cache[0] = 'x';
    }
}

void flush(void (*report)(void)) {
    free(cache);
    report();
    cache = NULL;
}
