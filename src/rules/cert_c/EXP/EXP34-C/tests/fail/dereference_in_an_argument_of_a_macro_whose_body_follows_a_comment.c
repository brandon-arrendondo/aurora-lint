/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the comment that spans lines inside the #define is one space, so the body is `printf X` and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) /* tracing
   */ printf X

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
