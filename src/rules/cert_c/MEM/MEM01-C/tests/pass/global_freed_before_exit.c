/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - a path that ends the process escapes nothing
 */

#include <stdlib.h>

char *cache;

void fatal(void) {
  free(cache);
  exit(1);
}
