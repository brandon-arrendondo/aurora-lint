/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a loop around the freeing loop, but not the store, clears an element after skipping the free
 *
 * The clear follows the freeing loop in the source, but the outer loop
 * runs it before the free's next iteration.
 */
#include <stdlib.h>
#include <string.h>
int f(int c){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++;
 while (c--) { if (c == 1) for (i = 0; i < n; i++) free(p[i]); p[0] = NULL; }
 return 0; }
