/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee reads ssl off an element of an array of struct values it declares
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
  struct other a[2];
  a[0].ssl = "x";
  c->engine = NULL;
  puts(a[0].ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
