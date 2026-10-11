/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - the global is set to NULL
 */

#include <stdlib.h>

char *cache;

void drop_cache(void) {
  free(cache);
  cache = NULL;
}
