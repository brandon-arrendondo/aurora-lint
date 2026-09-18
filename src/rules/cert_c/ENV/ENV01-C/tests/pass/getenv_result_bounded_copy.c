/*
 * Rule: ENV01-C
 * Source: task 1174
 * Status: PASS - the copy is bounded by the destination, or sized from the value
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f(void) {
  char copy[16];
  const char *temp = getenv("TEST_ENV");
  if (temp != NULL) {
    strncpy(copy, temp, sizeof copy - 1);
    copy[sizeof copy - 1] = '\0';
    snprintf(copy, sizeof copy, "%s", temp);
  }
}

void g(void) {
  const char *temp = getenv("TEST_ENV");
  if (temp != NULL) {
    size_t n = strlen(temp) + 1;
    char *path = malloc(n);
    if (path != NULL) {
      memcpy(path, temp, n);
      free(path);
    }
  }
}
