#include <stdlib.h>
#include "api.h"
API_INIT
struct conn { char *ssl; char *list; };
static void h(struct conn *c) { if (c->list) api_free(c->list); c->list = 0; }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
