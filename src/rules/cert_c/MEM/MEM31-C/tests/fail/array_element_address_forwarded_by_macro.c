/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a macro forwards the element's address to a callee that clears it
 *
 * The macro hands on `&(e)`, not the element's value, so it is no plain
 * read.
 */
#include <stdlib.h>
#include <string.h>
void reset(char **slot) { *slot = NULL; }
#define RESET_SLOT(e) reset(&(e))

int f(void){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); n++; RESET_SLOT(p[0]);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
