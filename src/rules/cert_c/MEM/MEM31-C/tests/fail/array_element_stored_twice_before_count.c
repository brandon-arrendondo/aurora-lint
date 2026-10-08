/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - p[n] is stored twice before n++, so the first block leaks
 *
 * The second store overwrites the first block; the loop can free only one.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); p[n] = malloc(8); n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
