/*
 * Rule: ERR04-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdlib.h>

void func(int something_really_bad) {
  if (something_really_bad) {
    abort();
  }
}