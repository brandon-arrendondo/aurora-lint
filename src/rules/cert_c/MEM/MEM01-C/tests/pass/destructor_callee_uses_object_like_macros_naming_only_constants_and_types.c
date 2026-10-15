/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee's object-like macros expand only to constants, keywords and a type the file declares, and the object is freed next
 */

#include <stdlib.h>

typedef unsigned int conn_flags;

struct conn {
  char *ssl;
  char *list;
  conn_flags flags;
};

#define CONN_CLOSED 0x2u
#define CONN_FLAGS_NONE ((conn_flags)0)
#define CONN_MARK (CONN_CLOSED | sizeof(struct conn))

static void conn_reset(struct conn *c) {
  c->flags = CONN_FLAGS_NONE;
  c->flags |= CONN_MARK;
  c->list = NULL;
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_reset(c);
  free(c);
}
