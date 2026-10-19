/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - TRACE drops __VA_ARGS__ in every arm, so q->fd is never evaluated
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef NEVER_SET_ANYWHERE
#define TRACE(...)
#else
#define TRACE(...) ((void)0)
#endif

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE("fd %d\n", q->fd);
  free(q);
  return 0;
}
