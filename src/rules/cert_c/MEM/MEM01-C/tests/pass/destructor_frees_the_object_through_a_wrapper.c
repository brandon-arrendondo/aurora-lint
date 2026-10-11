/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
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
