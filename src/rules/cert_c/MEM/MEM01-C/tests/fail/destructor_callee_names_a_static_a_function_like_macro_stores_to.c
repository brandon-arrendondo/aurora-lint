/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a function-like macro stores the object in the static the callee's macro names
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *log_target;
#define SET_LOG_TARGET(x) (log_target = (x))
#define LOG_TARGET log_target

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts("logging");
  }
}

void conn_free(struct conn *c) {
  SET_LOG_TARGET(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
