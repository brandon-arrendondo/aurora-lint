/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - the member is read before it is set
 */

#include <stdlib.h>

struct session {
  char *buf;
};

int release_and_peek(struct session *s) {
  free(s->buf);
  return s->buf[0];
}
