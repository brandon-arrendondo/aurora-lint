/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - TRACE is undefined at the call, which is then a call of a function that evaluates q->fd
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
#undef TRACE
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
