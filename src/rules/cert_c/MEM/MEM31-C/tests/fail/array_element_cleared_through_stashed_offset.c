/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the callee keeps v + 0 in a global, and a later call clears the element through it
 *
 * Storing a pointer derived from the parameter is a store of the parameter
 * all the same.
 */
#include <stdlib.h>
#include <string.h>
char **gsave;
static void keep2(char **v){ gsave = v + 0; }
static void reset2(void){ gsave[0] = NULL; }
int f(void){ char *p[16]; unsigned i, n = 0;
 keep2(p); p[n] = malloc(8); n++; reset2();
 for (i = 0; i < n; i++) free(p[i]); return 0; }
