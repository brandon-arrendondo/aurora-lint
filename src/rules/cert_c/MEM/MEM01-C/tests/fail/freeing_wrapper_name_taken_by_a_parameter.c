/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a function-pointer parameter spelled like the project's freeing wrapper is not that wrapper, so it does not free the object it is handed
 */

#include <stdlib.h>

struct session {
  char *buf;
};

static void release(void *p) {
  free(p);
}

void teardown(struct session *s) {
  release(s);
}

void d1(struct session *s, void (*release)(void *)) {
  free(s->buf);
  release(s);
}
