#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(conn_t *c) { if (c->u.raw) puts(c->u.raw); }
void f(conn_t *c) { free(c->u.ssl); h(c); free(c); }
