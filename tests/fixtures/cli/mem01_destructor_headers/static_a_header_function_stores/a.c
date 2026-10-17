#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static struct conn *log_target;
#include "set.h"
#define LOG_TARGET log_target
static void h(struct conn *c) { c->list = 0; if (LOG_TARGET) puts(LOG_TARGET->ssl); }
void f(struct conn *c) { set_log_target(c); free(c->ssl); h(c); free(c); }
