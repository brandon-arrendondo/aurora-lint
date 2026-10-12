/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: FAIL - the rand macro is inside an #if 0, so it is never
 * compiled and the call is the standard library's rand()
 */

#include <stdlib.h>

#if 0
#define rand() my_rand()
#endif

int pick(void) {
  return rand();
}
