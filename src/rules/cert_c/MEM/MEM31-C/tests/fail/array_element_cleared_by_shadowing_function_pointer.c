/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a block-local function pointer named like a harmless function clears the element
 *
 * The call resolves to the local object, not the static function of the
 * same name (ADR-0006).
 */
#include <stdlib.h>
#include <string.h>
static void clr(char **v){ v[0] = NULL; }
static void nop(char **v){ (void)v; }
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++;
 { void (*nop)(char **) = clr; nop(p); }
 for (i = 0; i < n; i++) free(p[i]); return 0; }
