/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee initializes a local struct from the object another function returns and reads ssl off the copy, which holds the freed address if that object is this one
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
  struct conn v = *get_log();
  c->engine = NULL;
  puts(v.ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
