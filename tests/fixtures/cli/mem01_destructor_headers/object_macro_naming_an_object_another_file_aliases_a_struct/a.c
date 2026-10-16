#include <stdlib.h>
#include <stdio.h>
struct conn { char *ssl; char *engine; };
struct conn *log_conn;
#define LOG_TARGET log_conn
static void h(struct conn *c) { c->engine = 0; if (LOG_TARGET) puts(LOG_TARGET->ssl); }
void f(struct conn *c) { log_conn = c; free(c->ssl); h(c); free(c); }
