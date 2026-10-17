/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee frees another field through a macro that calls through a static table of this file, which is only ever set to constants
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

struct routines {
  void (*free)(void *);
};

static const struct routines *api = 0;
#define api_free api->free

void api_reset(void) {
  api = NULL;
}

static void conn_reset(struct conn *c) {
  if (c->engine) {
    (void)api_free(c->engine);
  }
  c->engine = NULL;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_reset(c);
  free(c);
}
