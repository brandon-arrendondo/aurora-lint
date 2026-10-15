#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static void h(struct conn *c) { if (c->SSLF) puts(c->SSLF); }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
