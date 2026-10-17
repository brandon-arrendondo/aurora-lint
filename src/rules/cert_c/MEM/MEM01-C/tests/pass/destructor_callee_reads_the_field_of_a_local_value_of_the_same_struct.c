/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee reads ssl off a local struct conn value, a different object from the one whose member was freed
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
  struct conn l;
  l.ssl = "x";
  c->engine = NULL;
  puts(l.ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
