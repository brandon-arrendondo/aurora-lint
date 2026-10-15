/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee returns its parameter, which hands the object on, and the caller reads the freed member through the result
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *h(struct conn *c) {
  c->engine = NULL;
  return (c);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  struct conn *x = h(c);
  puts(x->ssl);
  free(c);
}
