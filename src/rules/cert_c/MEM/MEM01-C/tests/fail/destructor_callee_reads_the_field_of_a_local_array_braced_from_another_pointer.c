/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's local array is initialized with a copy of the object another function returns, so a[0].ssl may hold the freed address
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

struct conn *get_log(void);
void set_log(struct conn *c);

static void conn_log(struct conn *c) {
  struct conn a[1] = { *get_log() };
  c->engine = NULL;
  puts(a[0].ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
