/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a macro used as the field name hides the read of the freed member in the callee
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#define SSLF ssl
static void h(struct conn *c) {
  if (c->SSLF) puts(c->SSLF);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  h(c);
  free(c);
}
