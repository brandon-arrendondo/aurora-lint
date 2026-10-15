/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the object holding the freed member goes to a function this file defines whose body never reads that member, and the object is freed next
 */

#include <stdlib.h>

struct conn {
  char *ssl;
  char *engine;
  char *key;
};

static void engine_deinit(struct conn *c) {
  if (c->key) {
    free(c->key);
    c->key = NULL;
  }
  if (c->engine) {
    c->engine = NULL;
  }
}

void conn_free(struct conn *c) {
  if (c == NULL) {
    return;
  }
  free(c->ssl);
  engine_deinit(c);
  free(c);
}
