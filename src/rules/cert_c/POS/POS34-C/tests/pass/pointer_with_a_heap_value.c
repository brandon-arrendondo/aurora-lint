/*
 * Rule: POS34-C
 * Source: CERT POS34-C text (automatic storage)
 * Status: PASS - a pointer that may hold heap storage is not proven automatic
 */

#include <stdlib.h>
#include <string.h>

int func(const char *var, int use_heap) {
  char env[1024];
  char *entry = env;
  if (use_heap) {
    entry = strdup(var);
  }
  return putenv(entry);
}
