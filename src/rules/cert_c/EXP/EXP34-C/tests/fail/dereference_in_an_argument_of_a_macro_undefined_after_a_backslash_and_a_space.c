/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - gcc and clang splice a backslash followed by a space and a newline, so the line comment continues over `#undef TRACE` and `#define TRACE(X)`, the printing TRACE stays, and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) printf X
// tracing off \ 
#undef TRACE
// tracing off \ 
#define TRACE(X)

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
