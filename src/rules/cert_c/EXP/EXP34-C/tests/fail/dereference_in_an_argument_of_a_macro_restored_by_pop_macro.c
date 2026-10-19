/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - pop_macro restores the printing TRACE that push_macro saved, so q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) printf X
#pragma push_macro("TRACE")
#undef TRACE
#define TRACE(X)
#pragma pop_macro("TRACE")

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
