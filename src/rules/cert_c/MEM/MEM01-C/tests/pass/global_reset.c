/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - the global is set to NULL
 */

#include <stdlib.h>

char *cache;

void drop_cache(void) {
  free(cache);
  cache = NULL;
}
