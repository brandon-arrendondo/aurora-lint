/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the live arm of TRACE expands its argument, so q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#if 0
#define TRACE(X)
#else
#define TRACE(X) printf X
#endif

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
