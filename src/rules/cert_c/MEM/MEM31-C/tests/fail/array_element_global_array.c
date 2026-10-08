/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the array is a global that reset() may change
 *
 * A callee can replace a file-scope array's elements unseen.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(void){ unsigned i, n = 0;
 gp[n] = malloc(8); n++; reset();
 for (i = 0; i < n; i++) free(gp[i]); return 0; }
