/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the store sits in a while condition, which runs many times
 *
 * A store in a loop condition is repeated like one in its body.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(int c){ char *p[16]; unsigned i, n = 0;
 while ((p[n] = malloc(8)) != NULL) { if (c) break; }
 n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
