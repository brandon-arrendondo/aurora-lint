/*
 * Rule: POS34-C
 * Source: Maintainer ruling, POS34-C/2026-10-07/options
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 */

#include <stdlib.h>

int main(void) {
  char env[1024];
  snprintf(env, sizeof(env), "TEST=%d", 1);
  if (putenv(env) != 0) {
    return 1;
  }
  return 0;
}
