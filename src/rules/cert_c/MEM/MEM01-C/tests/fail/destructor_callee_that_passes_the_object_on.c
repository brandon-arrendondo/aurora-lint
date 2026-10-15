/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the function this file defines hands the object on to a function it cannot see, which can read the freed member
 */

#include <stdlib.h>

struct conn {
  char *ssl;
  char *engine;
};

extern void audit(struct conn *c);

static void engine_deinit(struct conn *c) {
  c->engine = NULL;
  audit(c);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  engine_deinit(c);
  free(c);
}
