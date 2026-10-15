/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads the freed member through a macro whose replacement names the parameter
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#define SSL_OF_C (c->ssl)
static void h(struct conn *c) {
  if (SSL_OF_C) puts(SSL_OF_C);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
