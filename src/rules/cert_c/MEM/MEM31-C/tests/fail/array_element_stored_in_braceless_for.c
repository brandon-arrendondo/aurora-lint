/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a braceless for stores p[n] three times before one n++
 *
 * The store is the whole body of a loop, so it runs many times and the
 * increment after the loop counts one of them.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(void){ char *p[16]; unsigned i, k, n = 0;
 for (k = 0; k < 3; k++) p[n] = malloc(8);
 n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
