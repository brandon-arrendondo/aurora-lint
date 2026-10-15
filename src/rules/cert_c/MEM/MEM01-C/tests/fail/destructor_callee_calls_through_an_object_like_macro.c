/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee's object-like macro expands to a call of a function the file defines, which reads the object through a static the caller set
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *current;

static void dump(void) {
  if (current) puts(current->ssl);
}

#define DUMP dump()

static void conn_log(struct conn *c) {
  c->engine = NULL;
  DUMP;
}

void conn_free(struct conn *c) {
  current = c;
  free(c->ssl);
  conn_log(c);
  free(c);
}
