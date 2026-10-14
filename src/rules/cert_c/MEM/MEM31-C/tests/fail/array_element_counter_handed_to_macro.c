/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the counter is handed to a macro that zeroes it
 */
#include <stdlib.h>
#define ZERO(x) ((x) = 0)

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++; ZERO(n);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
