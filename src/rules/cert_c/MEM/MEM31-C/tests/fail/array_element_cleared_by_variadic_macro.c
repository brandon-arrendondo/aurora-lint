/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a variadic macro whose body clears an element of the array
 *
 * A variadic definition is read from its arm, and this one names the array.
 */
#include <stdlib.h>
#include <string.h>
#define reset_first(...) (p[0] = NULL)

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; reset_first(1, 2);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
