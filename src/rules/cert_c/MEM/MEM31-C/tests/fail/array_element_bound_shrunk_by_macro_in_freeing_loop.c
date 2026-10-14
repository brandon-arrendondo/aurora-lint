/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a macro in the freeing loop's body sets the bound to zero after the first free
 */
#include <stdlib.h>
#define SHRINK() (n = 0)

int f(int k){ char *p[8]; unsigned i, n = 0; int j;
 for (j = 0; j < k && j < 8; j++) { p[n] = malloc(8); if (!p[n]) break; n++; }
 for (i = 0; i < n; i++) { free(p[i]); SHRINK(); } return 0; }
