/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - a failed store jumps to a label just before the freeing loop
 *
 * The goto stays inside the stretch from the store to the loop, so every
 * path from the store reaches the free.
 */
#include <stdlib.h>
#include <string.h>
int f(int c){ char *p[16]; unsigned i, n = 0;
 while (c-- > 0) {
  p[n] = malloc(8);
  if (!p[n]) goto fail;
  n++;
  if (n == 16) break; }
fail:
 for (i = 0; i < n; i++) free(p[i]); return 0; }
