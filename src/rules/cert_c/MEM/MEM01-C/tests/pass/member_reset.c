/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
