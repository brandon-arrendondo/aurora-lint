/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: FAIL - a cast around the freed pointer is still that pointer
 */

#include <stdlib.h>

int release_cast(char *p) {
  free((void *)p);
  return p == NULL;
}
