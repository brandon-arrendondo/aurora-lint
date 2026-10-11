/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - the array is the second declarator of its declaration
 */

#include <stdlib.h>

int func(const char *var) {
  char *unused = 0, env[1024];
  snprintf(env, sizeof(env), "TEST=%s", var);
  (void)unused;
  return putenv(env);
}
