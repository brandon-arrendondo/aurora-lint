/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - a block-scope extern declaration in another function names the static the callee's macro names, and stores the object in it
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

static void keep(struct conn *c) {
  extern struct conn *log_target;
  log_target = c;
}

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  keep(c);
  free(c->ssl);
  conn_log(c);
  free(c);
}
