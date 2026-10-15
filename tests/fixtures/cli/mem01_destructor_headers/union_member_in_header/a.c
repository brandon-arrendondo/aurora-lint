#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(struct conn *c) { if (c->u.raw) puts(c->u.raw); }
void f(struct conn *c) { free(c->u.ssl); h(c); free(c); }
