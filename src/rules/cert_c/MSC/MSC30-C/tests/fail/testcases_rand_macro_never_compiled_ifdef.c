/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: FAIL - the rand macro is inside an #ifdef of a name nothing defines, so it is never
 * compiled and the call is the standard library's rand()
 */

#include <stdlib.h>

#ifdef NEVER_DEFINED_XYZ
#define rand() my_rand()
#endif

int pick(void) {
  return rand();
}
