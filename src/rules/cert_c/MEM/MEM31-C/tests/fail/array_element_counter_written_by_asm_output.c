/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - an asm output operand writes the counter between the stores and the loop
 */
#include <stdlib.h>
int f(int k){ char *p[8]; unsigned i, n = 0; int j;
 for (j = 0; j < k && j < 8; j++) { p[n] = malloc(8); if (!p[n]) break; n++; }
 __asm__ volatile("" : "+r"(n));
 for (i = 0; i < n; i++) free(p[i]); return 0; }
