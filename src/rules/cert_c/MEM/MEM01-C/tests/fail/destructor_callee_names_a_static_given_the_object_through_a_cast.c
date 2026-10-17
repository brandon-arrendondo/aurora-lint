/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the static the callee's macro names is given the object through a cast, so it may hold it
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
#define API api

static void conn_log(struct conn *c) {
  c->engine = NULL;
  puts(((const struct conn *)API)->ssl);
}

void conn_free(struct conn *c) {
  api = (const struct routines *)c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
