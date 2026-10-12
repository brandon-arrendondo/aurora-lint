/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the callee copies its parameter to a local and clears the element through the copy
 *
 * A write through a local copy of the parameter is an unnamed location,
 * not a write through the parameter, and still clears the element.
 */
#include <stdlib.h>
#include <string.h>
static void clr(char **v){ char **q = v; q[0] = NULL; }
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; clr(p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
