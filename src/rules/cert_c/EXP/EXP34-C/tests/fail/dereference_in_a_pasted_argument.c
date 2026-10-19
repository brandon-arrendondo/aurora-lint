/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - a paste joins only the argument's first token (trace_x + q->fd), so q->fd is still evaluated
 */

#include <stdio.h>
#include <stdlib.h>

int trace_x;
#define TRACE(X) (void)(trace_ ## X)

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(x + q->fd);
  free(q);
  return 0;
}
