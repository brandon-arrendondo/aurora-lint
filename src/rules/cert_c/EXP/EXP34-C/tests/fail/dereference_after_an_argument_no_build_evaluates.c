/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - q->fd in TRACE's argument is never evaluated, since the live TRACE is empty, but the return dereferences q while it may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#if 0
#define TRACE(X) printf X
#else
#define TRACE(X)
#endif

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  return q->fd;
}
