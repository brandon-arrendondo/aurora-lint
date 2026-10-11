/*
 * Rule: MSC30-C
 * Source: testcases
 * Status: FAIL - a parenthesized callee still names the library's rand()
 */

#include <stdlib.h>

int pick(void) {
  return (rand)() % 10;
}
