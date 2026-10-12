/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the callee memsets the array it is handed, through a library call its effects do not record as a write
 *
 * A library call with a side effect inside the callee writes through the
 * parameter, though the callee's own writes list nothing.
 */
#include <stdlib.h>
#include <string.h>
static void clr(char **v){ memset(v, 0, 16 * sizeof *v); }
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; clr(p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
