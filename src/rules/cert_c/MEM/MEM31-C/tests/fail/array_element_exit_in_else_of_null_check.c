/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a break in the else of if (!p[n]) leaves with p[n] held
 *
 * Only the branch taken when the element is null may leave before n++;
 * the else branch runs with the block stored and uncounted.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(int c, int d){ char *p[16]; unsigned i, n = 0;
 for (;;) { p[n] = malloc(8); if (!p[n]) { } else if (d) break; n++; if (c) break; }
 for (i = 0; i < n; i++) free(p[i]); return 0; }
