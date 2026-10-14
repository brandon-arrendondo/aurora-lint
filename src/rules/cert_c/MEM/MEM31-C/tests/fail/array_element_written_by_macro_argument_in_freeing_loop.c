/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the freeing loop hands each element to a macro that clears it before the free
 */
#include <stdlib.h>
#define CLR(e) ((e) = NULL)

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++;
 for (i = 0; i < n; i++) { CLR(p[i]); free(p[i]); } return 0; }
