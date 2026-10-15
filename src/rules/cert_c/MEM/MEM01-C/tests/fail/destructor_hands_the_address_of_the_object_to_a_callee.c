/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the address of the pointer to the object is handed on, and the callee reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static void conn_log(struct conn **pc) {
  if ((*pc)->ssl) puts((*pc)->ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(&c);
  free(c);
}
