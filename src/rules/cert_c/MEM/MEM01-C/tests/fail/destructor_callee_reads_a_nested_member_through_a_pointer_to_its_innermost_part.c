/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads ssl through a pointer another function returns, which may point at c->a.t, the struct the freed member is a field of
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

struct tls *get_tls(void);

static void conn_log(struct conn *c) {
  struct tls *t = get_tls();
  c->engine = NULL;
  if (t) puts(t->ssl);
}

void conn_free(struct conn *c) {
  free(c->a.t.ssl);
  conn_log(c);
  free(c);
}
