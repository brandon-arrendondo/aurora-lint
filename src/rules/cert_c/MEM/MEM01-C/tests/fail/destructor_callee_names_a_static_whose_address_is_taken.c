/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the address of the static the callee's macro names is taken, so a store through it is not seen
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static struct conn *log_target;
#define LOG_TARGET log_target

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  memcpy(&log_target, &c, sizeof c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
