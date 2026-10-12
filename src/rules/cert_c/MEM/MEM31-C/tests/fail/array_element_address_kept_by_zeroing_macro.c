/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a zeroing macro that also hands the array's address to another call
 *
 * Only a macro that is exactly one zeroing call on its own first parameter
 * counts as zeroing.
 */
#include <stdlib.h>
#include <string.h>
void stash(void *x);
void reset(void);
#define ZERO(s, c, n) memset(s, c, n), stash(s)
int f(void){ char *p[16]; unsigned i, n = 0;
 ZERO(&p, 0, sizeof p); p[n] = malloc(8); n++; reset();
 for (i = 0; i < n; i++) free(p[i]); return 0; }
