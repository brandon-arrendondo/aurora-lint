/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a macro whose body resets the counter runs between the store and the loop
 *
 * `n` no longer counts the store once `RESET()` expands, so the loop frees
 * nothing.
 */
#include <stdlib.h>
#define RESET() (n = 0)

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++; RESET();
 for (i = 0; i < n; i++) free(p[i]); return 0; }
