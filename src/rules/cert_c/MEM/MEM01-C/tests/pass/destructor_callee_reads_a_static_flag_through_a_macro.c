/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: PASS - the callee's macro names a static flag of this file that is only ever set to constants, so it cannot hold the object, and the object is freed next
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct conn {
  char *ssl;
  char *engine;
};

static int trace_on = 0;
#define TRACE_ON trace_on

void trace_enable(void) {
  trace_on = 1;
}

static void conn_log(struct conn *c) {
  c->engine = NULL;
  if (TRACE_ON) {
    puts("closing");
  }
}

void conn_free(struct conn *c) {
  free(c->ssl);
  conn_log(c);
  free(c);
}
