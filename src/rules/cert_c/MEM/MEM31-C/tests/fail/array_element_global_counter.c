/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the counter is a global that reset() may change
 *
 * A callee can rewrite a file-scope counter between the count and the
 * loop, so the loop's range is not known to cover the store.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(void){ char *p[16]; unsigned i;
 p[gn] = malloc(8); gn++; reset();
 for (i = 0; i < gn; i++) free(p[i]); return 0; }
