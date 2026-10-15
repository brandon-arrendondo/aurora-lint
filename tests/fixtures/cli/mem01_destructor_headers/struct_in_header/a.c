#include <stdlib.h>
#include "conn.h"
static void h(struct conn *c) { c->engine = 0; c->u.a = 1; }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
