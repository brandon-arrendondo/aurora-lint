/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - the counter is handed to a macro whose definition never pastes that argument
 */
#include <stdlib.h>
#define TRACE(level, x) ((void)(level))

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++; TRACE(1, n);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
