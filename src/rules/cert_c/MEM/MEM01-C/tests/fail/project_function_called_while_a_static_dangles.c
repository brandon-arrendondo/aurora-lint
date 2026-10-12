/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a function the project defines can read the static that still holds the freed address
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
