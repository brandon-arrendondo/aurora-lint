#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(struct conn *c) { if (c->in.raw) puts(c->in.raw); }
void f(struct conn *c) { free(c->in.ssl); h(c); free(c); }
