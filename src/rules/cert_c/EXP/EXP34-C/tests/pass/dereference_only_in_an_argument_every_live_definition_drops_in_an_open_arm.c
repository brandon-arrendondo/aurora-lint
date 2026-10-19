/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - the whole file sits in an #ifndef with no #else, and every build compiling the call took the #else arm whose TRACE drops its argument, so no build evaluates q->fd
 */

#ifndef CONN_OMIT_FILE

#include <stdio.h>
#include <stdlib.h>

#if 0
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

#endif
