/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads `raw`, which is a union with the freed `ssl`
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  union {
    char *ssl;
    char *raw;
  };
  char *engine;
};

static void h(struct conn *c) {
  if (c->raw) puts(c->raw);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
