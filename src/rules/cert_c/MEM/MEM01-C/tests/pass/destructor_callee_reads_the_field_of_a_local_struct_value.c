/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee reads ssl only off a struct value it declares itself, which cannot be the freed object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

struct other {
  char *ssl;
  int n;
};

static void conn_log(struct conn *c) {
  struct other o;
  o.ssl = "x";
  c->engine = NULL;
  puts(o.ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
