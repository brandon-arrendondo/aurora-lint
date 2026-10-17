/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads ssl through its second parameter, which the caller may have pointed at the same object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
  struct conn *peer;
};

static void conn_report(struct conn *c, struct conn *other) {
  c->engine = NULL;
  if (other) puts(other->ssl);
}

void conn_free(struct conn *c, struct conn *last) {
  free(c->ssl);
  conn_report(c, last);
  free(c);
}
