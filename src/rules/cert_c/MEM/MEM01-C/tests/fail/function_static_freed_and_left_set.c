/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: FAIL - a function-local static outlives the function
 */

#include <stdlib.h>

void reset_buffer(void) {
  static char *buffer;
  free(buffer);
}
