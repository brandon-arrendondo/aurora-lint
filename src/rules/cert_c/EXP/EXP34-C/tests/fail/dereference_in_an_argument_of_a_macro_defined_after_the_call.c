/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the empty TRACE is defined only after the call, which is a call of a function that evaluates q->fd
 */

#include <stdio.h>
#include <stdlib.h>

void TRACE(int fd);

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(q->fd);
  free(q);
  return 0;
}

#define TRACE(X)
