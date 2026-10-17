/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads t.ssl through a pointer another function returns, which may point at c->a, the part of the object the freed member lives in
 */

#include <stdlib.h>
#include <stdio.h>

struct tls {
  char *ssl;
  int k;
};

struct inner {
  struct tls t;
  int z;
};

struct conn {
  struct inner a;
  char *engine;
};

struct inner *get_inner(void);

static void conn_log(struct conn *c) {
  struct inner *i = get_inner();
  c->engine = NULL;
  if (i) puts(i->t.ssl);
}

void conn_free(struct conn *c) {
  free(c->a.t.ssl);
  conn_log(c);
  free(c);
}
