/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a macro whose body names the array clears the element
 *
 * What the macro expands to is not in the tree; its definition spells the
 * array.
 */
#include <stdlib.h>
#include <string.h>
#define CLR0 (p[0] = NULL)
#define CLR() CLR0
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; CLR();
 for (i = 0; i < n; i++) free(p[i]); return 0; }
