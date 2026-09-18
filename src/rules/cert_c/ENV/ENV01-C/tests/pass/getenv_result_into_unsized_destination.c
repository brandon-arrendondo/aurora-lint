/*
 * Rule: ENV01-C
 * Source: task 1174
 * Status: PASS - a local getenv() result copied somewhere whose size the
 *         rule cannot see (a pointer parameter, a heap block) is not a
 *         reported assumption; only a fixed-size array carries one
 */

#include <stdlib.h>
#include <string.h>

void f(char *out) {
  const char *home = getenv("HOME");
  if (home != NULL) {
    strcpy(out, home);
  }
}

char *g(void) {
  const char *home = getenv("HOME");
  char *copy = NULL;
  if (home != NULL) {
    copy = malloc(strlen(home) + 1);
    if (copy != NULL) {
      strcpy(copy, home);
    }
  }
  return copy;
}
