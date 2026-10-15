#include <stdio.h>
struct conn { char *ssl; char *engine; };
#define LOG_CLOSE(m) puts(c->ssl ? c->ssl : (m))
