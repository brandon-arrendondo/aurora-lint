/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - the #undef of TRACE_ON is inside a comment, so TRACE_ON stays defined, the #ifdef arm that makes TRACE print is live, and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
#define TRACE_ON
/*
#undef TRACE_ON
*/
#ifdef TRACE_ON
#undef TRACE
#define TRACE(X) printf X
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
