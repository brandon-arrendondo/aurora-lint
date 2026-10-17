/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee declares its pointer as conn_p (log_conn) and reads the freed member through it; the pointer comes from a function the scan cannot see and may be the object
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
  struct conn *peer;
};

typedef struct conn *conn_p;
typedef int log_conn;
void set_log(struct conn *c);
struct conn *get_log(void);

static void conn_log(struct conn *c) {
  conn_p (log_conn) = get_log();
  c->engine = NULL;
  if (log_conn) puts(log_conn->ssl);
}

void conn_free(struct conn *c) {
  set_log(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
