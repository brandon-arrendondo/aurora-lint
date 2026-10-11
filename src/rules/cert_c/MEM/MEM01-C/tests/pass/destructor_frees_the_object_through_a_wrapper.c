/*
 * Rule: MEM01-C
 * Source: CERT MEM01-C text; maintainer ruling that "immediately" means before the pointer can next be read or escape
 * Status: PASS - the object is freed next through a wrapper whose body frees it
 */

#include <stdlib.h>

struct session {
  char *buf;
  char *name;
};

static void release(void *p) {
  free(p);
}

void destroy_session(struct session *s) {
  free(s->buf);
  free(s->name);
  release(s);
}
