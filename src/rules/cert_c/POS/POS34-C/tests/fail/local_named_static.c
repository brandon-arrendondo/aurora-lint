/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - a name containing 'static' does not give static storage
 */

#include <stdlib.h>

int func(const char *var) {
  char static_env[1024];
  snprintf(static_env, sizeof(static_env), "TEST=%s", var);
  return putenv(static_env);
}
