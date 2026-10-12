/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - the callee only reads the array, and its value is discarded
 *
 * A callee that writes nothing, stores nothing and returns nothing used
 * leaves the elements to the freeing loop.
 */
#include <stdlib.h>
#include <string.h>
static int nop(char **v){ return v[0] != 0; }
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; nop(p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
