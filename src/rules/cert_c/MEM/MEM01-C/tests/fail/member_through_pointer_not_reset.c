/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
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
