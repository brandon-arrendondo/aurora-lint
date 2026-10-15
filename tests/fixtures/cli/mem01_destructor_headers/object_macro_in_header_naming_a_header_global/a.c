#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(struct conn *c) { c->engine = 0; if (LOG_TARGET) puts(LOG_TARGET->ssl); }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
