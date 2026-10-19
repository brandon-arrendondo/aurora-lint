/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - TRACE only stringizes its argument, so q->fd is text, never evaluated
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) puts(#X)

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(q->fd);
  free(q);
  return 0;
}
