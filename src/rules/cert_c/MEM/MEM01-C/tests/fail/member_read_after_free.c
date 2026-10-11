/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
