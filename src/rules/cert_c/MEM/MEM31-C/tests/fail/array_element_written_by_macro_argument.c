/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a function-like macro handed an element assigns it
 *
 * A macro's argument is text it pastes, not a value it reads: `CLR` clears
 * the element between the store and the loop.
 */
#include <stdlib.h>
#include <string.h>
#define CLR(e) ((e) = NULL)

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++; CLR(p[0]);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
