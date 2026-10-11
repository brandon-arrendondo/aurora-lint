/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
 * Status: FAIL - a member of the caller's object keeps the freed address
 */

#include <stdlib.h>

struct session {
  char *buf;
  int len;
};

void release_buffer(struct session *s) {
  free(s->buf);
  s->len = 0;
}
