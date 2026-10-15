/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the function this file defines reads the freed member through the object it is handed, so the object is not exempt for being freed next
 */

#include <stdlib.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static void engine_deinit(struct conn *c) {
  if (c->ssl != NULL && strlen(c->ssl) > 0) {
    c->engine = NULL;
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  engine_deinit(c);
  free(c);
}
