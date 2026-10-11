/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - the address of an automatic array's element
 */

#include <stdlib.h>

int func(const char *var) {
  char env[1024];
  snprintf(env, sizeof(env), "TEST=%s", var);
  return putenv(&env[0]);
}
