#include <stdlib.h>
#include "conn.h"
static void h(struct conn *c) { LOG_CLOSE("closing"); c->engine = 0; }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
