/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the address of the struct member that holds the freed pointer is handed on, and the callee reads it
 */

#include <stdlib.h>
#include <stdio.h>

struct tls {
  char *ssl;
  char *raw;
};

struct conn {
  struct tls tls;
};

static void tls_log(struct tls *t) {
  puts(t->ssl);
}

void conn_free(struct conn *c) {
  free(c->tls.ssl);
  tls_log(&c->tls);
  free(c);
}
