/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the static the callee's macro names is handed to a function-like macro whose replacement may store the object in it, and the callee reads the member through it
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

#define SET(a, b) ((a) = (b))
static struct conn *log_target;
#define LOG_TARGET log_target

static void conn_log(struct conn *c) {
  c->engine = NULL;
  puts(LOG_TARGET->ssl);
}

void conn_free(struct conn *c) {
  SET(log_target, c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
