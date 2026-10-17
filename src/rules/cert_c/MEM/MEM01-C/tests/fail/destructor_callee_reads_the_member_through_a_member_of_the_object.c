/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads ssl through c->peer, which may point back to the object whose member was freed
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
  struct conn *peer;
};

static void conn_unlink(struct conn *c) {
  if (c->peer) puts(c->peer->ssl);
  c->engine = NULL;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_unlink(c);
  free(c);
}
