/*
 * Rule: MSC14-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#define _XOPEN_SOURCE 600
#include <string.h>
#include <stdio.h>
#include <errno.h>
void f() {
  char buf[BUFSIZ];
  int result;

  result = strerror_r(errno, buf, sizeof buf);

  if (0 != result) {
    strcpy(buf, "Unknown error");
  }
  fprintf(stderr, "Error: %s\n", buf);
}