/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the static is an argument of a call nothing in the scan declares, which may be a macro that stores the object in it
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

void log_to(struct conn *c) {
  STORE_POINTER(log_target, c);
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
