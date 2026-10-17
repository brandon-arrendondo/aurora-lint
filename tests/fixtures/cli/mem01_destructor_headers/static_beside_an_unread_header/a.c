#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
#include "generated/log_hooks.h"
static struct conn *log_target;
#define LOG_TARGET log_target
static void h(struct conn *c) { c->list = 0; if (LOG_TARGET) puts(LOG_TARGET->ssl); }
void f(struct conn *c) { KEEP_LOG_TARGET(c); free(c->ssl); h(c); free(c); }
