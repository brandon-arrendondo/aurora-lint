/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee reads ssl off a union value it declares
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

union u {
  char *ssl;
  long v;
};

static void conn_log(struct conn *c) {
  union u x;
  x.v = 0;
  c->engine = NULL;
  printf("%p", (void *)x.ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
