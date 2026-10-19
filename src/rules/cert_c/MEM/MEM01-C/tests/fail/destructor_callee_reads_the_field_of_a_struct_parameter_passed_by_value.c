/*
 * Rule: MEM01-C
 * Source: synthetic
 * Status: FAIL - the callee reads ssl off a struct parameter passed by value, which the caller fills with *last, and last may be the object whose member was freed
 */

#include <stdlib.h>
#include <stdio.h>

struct conn {
  char *ssl;
  char *engine;
};

struct conn *get_log(void);
void set_log(struct conn *c);

static void conn_report(struct conn *c, struct conn other) {
  c->engine = NULL;
  puts(other.ssl);
}

void conn_free(struct conn *c, struct conn *last) {
  free(c->ssl);
  conn_report(c, *last);
  free(c);
}
