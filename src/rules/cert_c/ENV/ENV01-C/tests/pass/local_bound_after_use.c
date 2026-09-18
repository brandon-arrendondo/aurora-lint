/*
 * Rule: ENV01-C
 * Source: task 1174
 * Status: PASS - the name is bound to getenv() only after the copy
 */

#include <stdlib.h>
#include <string.h>

void f(const char *arg) {
  char copy[16];
  const char *temp = arg;
  strcpy(copy, "fixed");
  (void)temp;
  temp = getenv("TEST_ENV");
  (void)temp;
}
