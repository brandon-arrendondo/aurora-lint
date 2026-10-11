/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: FAIL - a local pointer whose only value is an automatic array
 */

#include <stdlib.h>

int func(const char *var) {
  char env[1024];
  char *entry = env;
  snprintf(env, sizeof(env), "TEST=%s", var);
  return putenv(entry);
}
