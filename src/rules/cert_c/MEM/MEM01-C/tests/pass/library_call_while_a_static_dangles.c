/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - a library function cannot read the program's static before it is reset
 */

#include <stdio.h>
#include <stdlib.h>

static char *cache;

void flush(void) {
    free(cache);
    puts("flushed");
    cache = NULL;
}
