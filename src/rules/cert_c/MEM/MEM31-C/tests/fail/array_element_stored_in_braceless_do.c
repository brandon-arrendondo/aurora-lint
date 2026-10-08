/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a braceless do-while stores p[n] repeatedly before one n++
 *
 * The same with a do loop.
 */
#include <stdlib.h>
void reset(void);
void maybe_free(void *q);
int flag;
unsigned gn;
char *gp[16];
struct S { unsigned n; char *a[16]; };

int f(int c){ char *p[16]; unsigned i, n = 0;
 do p[n] = malloc(8); while (c--);
 n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
