/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - a function-local static outlives the function
 */

#include <stdlib.h>

void reset_buffer(void) {
  static char *buffer;
  free(buffer);
}
