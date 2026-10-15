/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's object-like macro expands to another one whose replacement names the parameter
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

#define SSL_OF_C (c->ssl)
#define CURRENT_SSL SSL_OF_C

static void conn_log(struct conn *c) {
  if (CURRENT_SSL) puts(CURRENT_SSL);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
