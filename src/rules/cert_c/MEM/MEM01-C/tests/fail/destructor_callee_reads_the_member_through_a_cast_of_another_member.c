/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee casts the address of the object's first member back to the struct and reads the freed member through it
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *engine;
  char *ssl;
};

static void conn_log(struct conn *c) {
  struct conn *again = (struct conn *)&c->engine;
  puts(again->ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
