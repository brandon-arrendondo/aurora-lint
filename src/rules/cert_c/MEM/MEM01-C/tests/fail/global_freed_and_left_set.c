/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - a global outlives the function still holding the freed address
 */

#include <stdlib.h>

char *cache;

void drop_cache(void) {
  free(cache);
}
