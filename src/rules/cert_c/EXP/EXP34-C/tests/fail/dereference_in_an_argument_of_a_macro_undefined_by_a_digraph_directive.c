/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - %: is the digraph of #, so %:undef is a directive, TRACE is a function at the call and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
%:undef TRACE

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
