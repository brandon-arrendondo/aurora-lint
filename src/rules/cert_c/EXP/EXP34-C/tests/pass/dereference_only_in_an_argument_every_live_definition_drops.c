/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - TRACE's tracing arm is under #if 0, so the live definition drops its argument and no build evaluates q->fd
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
  free(q);
  return 0;
}
