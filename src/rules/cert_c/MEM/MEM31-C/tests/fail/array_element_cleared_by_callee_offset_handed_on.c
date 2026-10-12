/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the callee hands v + 0 to a helper that clears the element
 *
 * Pointer arithmetic on the parameter hides it from the helper's mapping,
 * which records the write as an unnamed location.
 */
#include <stdlib.h>
#include <string.h>
static void clr1(char **w){ w[0] = NULL; }
static void clr(char **v){ clr1(v + 0); }
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; clr(p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
