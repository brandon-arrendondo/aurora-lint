/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - a DEBUG build expands TRACE's argument, so q->fd is evaluated there while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG
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
