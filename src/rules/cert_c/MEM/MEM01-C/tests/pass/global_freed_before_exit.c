/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - a path that ends the process escapes nothing
 */

#include <stdlib.h>

char *cache;

void fatal(void) {
  free(cache);
  exit(1);
}
