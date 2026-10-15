/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's object-like macro names an object that another macro declares at file scope, where the caller may have stored the object
 */

#include <stdlib.h>

struct api_routines {
  void (*free)(void *);
};

#define API_INIT const struct api_routines *api = 0;
#define api_free api->free

API_INIT

struct conn {
  char *ssl;
  char *list;
};

static void conn_reset(struct conn *c) {
  if (c->list) {
    api_free(c->list);
  }
  c->list = NULL;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_reset(c);
  free(c);
}
