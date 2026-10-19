/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - TRACE drops its argument where it is defined, but the header included after it may redefine TRACE to print it, so q->fd may be evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
#include "conn_trace.h"

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
