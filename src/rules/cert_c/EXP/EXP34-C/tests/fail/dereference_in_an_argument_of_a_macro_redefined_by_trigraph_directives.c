/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - in strict ISO C before C23, `??=` is `#`, so TRACE is redefined to print and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
??=undef TRACE
??=define TRACE(X) printf X

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
