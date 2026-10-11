/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - the member dies with the object that holds it
 */

#include <stdlib.h>

struct session {
  char *buf;
  char *name;
};

void destroy_session(struct session *s) {
  free(s->buf);
  free(s->name);
  free(s);
}
