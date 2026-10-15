#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
CONN_LOG_INIT
static void h(struct conn *c) { c->engine = 0; if (log_conn) puts(log_conn->ssl); }
void f(struct conn *c) { log_conn = c; free(c->ssl); h(c); free(c); }
