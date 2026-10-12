/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a backward goto reruns a clear that sits before the store
 *
 * The goto makes a loop around the store, so a clear before it runs after
 * an earlier store.
 */
#include <stdlib.h>
#include <string.h>
int f(void){ char *p[16]; unsigned i, n = 0;
again:
 p[0] = NULL;
 p[n] = malloc(8); n++;
 if (n < 2) goto again;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
