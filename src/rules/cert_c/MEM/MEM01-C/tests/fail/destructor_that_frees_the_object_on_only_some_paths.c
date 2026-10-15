/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee leaves the member alone, but one path returns without freeing the object, so the member outlives the function holding the freed address
 */

#include <stdlib.h>

struct conn {
  char *ssl;
  char *engine;
};

static void engine_deinit(struct conn *c) {
  c->engine = NULL;
}

void conn_free(struct conn *c, int keep) {
  free(c->ssl);
  engine_deinit(c);
  if (keep) {
    return;
  }
  free(c);
}
