/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the empty TRACE is defined under #ifdef DEBUG_OFF inside another call's argument list, where the parser blanks the directives, so a build without DEBUG_OFF keeps the printing TRACE and evaluates q->fd while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) printf X

int pick(int, int);
int chosen;

void choose(void) {
  chosen = pick(1,
#ifdef DEBUG_OFF
#undef TRACE
#define TRACE(X)
#endif
                2);
}

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
