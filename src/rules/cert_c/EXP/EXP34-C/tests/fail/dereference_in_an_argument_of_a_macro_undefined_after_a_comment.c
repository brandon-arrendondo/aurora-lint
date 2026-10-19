/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the #undef after the comment on its line is a directive, so TRACE is a function at the call and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
/* re-enable tracing */ #undef TRACE

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
