/*
 * Rule: MEM01-C
 * Source: Maintainer ruling, rulings walk-through Q40 (MEM01-C)
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
