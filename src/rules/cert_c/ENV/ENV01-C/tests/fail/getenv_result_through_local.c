/*
 * Rule: ENV01-C
 * Source: real-world shape
 * Status: FAIL - the getenv() result reaches strcpy through a local
 */

#include <stdlib.h>
#include <string.h>

void f(void) {
  char copy[16];
  const char *temp = getenv("TEST_ENV");
  if (temp != NULL) {
    strcpy(copy, temp);
  }
}

void g(void) {
  static char out[32] = "prefix:";
  char *home = (char *)getenv("HOME");
  strcat(out, home);
}
