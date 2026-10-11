/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: PASS - the member is set to NULL
 */

#include <stdlib.h>

struct session {
  char *buf;
};

void release_buffer(struct session *s) {
  free(s->buf);
  s->buf = NULL;
}
