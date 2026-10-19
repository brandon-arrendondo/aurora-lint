/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the destructor handed the object to a function the scan cannot see, and the callee reads the freed member through the pointer another such function returns, which may be the object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
  struct conn *peer;
};

void set_log(struct conn *c);
struct conn *get_log(void);

static void conn_log(struct conn *c) {
  struct conn *log_conn = get_log();
  c->engine = NULL;
  if (log_conn) puts(log_conn->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
