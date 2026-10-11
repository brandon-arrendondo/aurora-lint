/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - a cast around the freed pointer is still that pointer
 */

#include <stdlib.h>

int release_cast(char *p) {
  free((void *)p);
  return p == NULL;
}
