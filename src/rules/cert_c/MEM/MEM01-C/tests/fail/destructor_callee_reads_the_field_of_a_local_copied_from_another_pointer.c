/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee copies the object another function returns into a local and reads ssl off the copy, which holds the freed address if that object is this one
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

struct conn *get_log(void);

static void conn_log(struct conn *c) {
  struct conn tmp;
  memcpy(&tmp, get_log(), sizeof tmp);
  c->engine = NULL;
  puts(tmp.ssl);
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
