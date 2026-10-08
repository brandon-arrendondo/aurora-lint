/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - p is pointed at another array before the loop frees p[i]
 *
 * The loop frees other[0..n-1], not the elements stored through buf.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(char **other){ char *buf[16]; char **p = buf; unsigned i, n = 0;
 p[n] = malloc(8); n++; p = other;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
