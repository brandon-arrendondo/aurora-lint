#include <stdlib.h>
#include "conn.h"
static void h(struct conn *c) { c->flags = CONN_RESET_FLAGS; c->list = 0; }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
