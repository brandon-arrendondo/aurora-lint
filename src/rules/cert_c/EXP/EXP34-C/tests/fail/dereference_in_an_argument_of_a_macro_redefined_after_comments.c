/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the #undef and #define after the comments on their lines are directives, so TRACE prints its argument and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
/**/ #undef TRACE
/**/ #define TRACE(X) printf X

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
