/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - an asm output operand writes the element
 *
 * An element that is neither read nor plainly assigned is something the
 * walk cannot follow.
 */
#include <stdlib.h>
#include <string.h>
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; __asm__("" : "=r"(p[0]));
 for (i = 0; i < n; i++) free(p[i]); return 0; }
