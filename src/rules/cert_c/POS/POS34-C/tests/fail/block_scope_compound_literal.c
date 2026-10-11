/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - a block-scope compound literal of array type
 */

#include <stdlib.h>

int func(void) {
  return putenv((char[]){"TEST=1"});
}
