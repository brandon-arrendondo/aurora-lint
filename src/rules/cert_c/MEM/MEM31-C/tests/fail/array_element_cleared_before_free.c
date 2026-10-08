/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the loop sets p[i] = NULL and then frees it
 *
 * Clearing the element first leaves the free with nothing to release.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++;
 for (i = 0; i < n; i++) { p[i] = NULL; free(p[i]); } return 0; }
