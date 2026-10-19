/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the splice joins `fd` and `x` into the parameter `fdx`, so the body prints its argument and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(fdx) printf("%d\n", fd\
x)

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
