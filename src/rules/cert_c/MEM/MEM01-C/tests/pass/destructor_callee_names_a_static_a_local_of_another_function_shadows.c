/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - another function keeps the object in a local that shares the static's name, which is another object; the static the callee's macro names is only ever set to NULL
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

void log_peek(struct conn *c) {
  struct conn *log_target = c;
  puts(log_target->ssl);
}

void log_reset(void) {
  log_target = NULL;
}

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (LOG_TARGET) {
    puts(LOG_TARGET->ssl);
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
