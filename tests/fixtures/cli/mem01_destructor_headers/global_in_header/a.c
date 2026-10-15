#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(struct conn *c) { c->engine = 0; if (g_last) puts(g_last->ssl); }
void f(struct conn *c) { g_last = c; free(c->ssl); h(c); free(c); }
