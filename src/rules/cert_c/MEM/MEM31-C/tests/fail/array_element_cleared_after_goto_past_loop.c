/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a goto jumps past the freeing loop to clear the element, then back
 *
 * The clear lies outside the stretch from the store to the loop, but a
 * path from the store to the loop runs it.
 */
#include <stdlib.h>
#include <string.h>
int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; goto clear;
back:
 for (i = 0; i < n; i++) free(p[i]); return 0;
clear:
 p[0] = NULL; goto back; }
