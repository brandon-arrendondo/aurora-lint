/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - `#undef SILENT` runs only in a build with VERBOSE, so a build with SILENT and without VERBOSE takes the #ifdef SILENT arm, which defines the printing TRACE, and q->fd is evaluated while q may be NULL
 */

#include <stdio.h>
#include <stdlib.h>

#define TRACE(X)
#ifdef VERBOSE
#undef SILENT
#endif
#ifdef SILENT
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
