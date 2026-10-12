/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the callee returns its parameter, and the caller clears the element through the result
 *
 * A callee that stores nothing can still hand the array back.
 */
#include <stdlib.h>
#include <string.h>
static char **id2(char **v){ return v; }
int f(void){ char *p[16]; char **q; unsigned i, n = 0;
 q = id2(p); p[n] = malloc(8); n++; q[0] = NULL;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
