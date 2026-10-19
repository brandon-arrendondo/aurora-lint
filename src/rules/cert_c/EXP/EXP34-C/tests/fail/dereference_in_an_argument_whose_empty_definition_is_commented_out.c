/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the empty TRACE sits inside a comment, so the live definition prints its argument and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X) printf X
/* tracing off:
#define TRACE(X)
*/

struct conn {
  int fd;
};

int conn_open(void) {
  struct conn *q = malloc(sizeof *q);
  TRACE(("fd %d\n", q->fd));
  free(q);
  return 0;
}
