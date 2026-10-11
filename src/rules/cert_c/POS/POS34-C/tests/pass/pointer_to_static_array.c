/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: PASS - a pointer copy of a static array
 */

#include <stdlib.h>

int func(const char *var) {
  static char env[1024];
  char *entry = env;
  snprintf(env, sizeof(env), "TEST=%s", var);
  return putenv(entry);
}
