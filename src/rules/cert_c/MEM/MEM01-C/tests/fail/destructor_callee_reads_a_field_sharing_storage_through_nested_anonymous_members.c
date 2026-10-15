/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads `raw`, which shares storage with the freed `ssl` inside an anonymous struct of an anonymous union
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  union {
    struct {
      char *ssl;
      char *e2;
    };
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
