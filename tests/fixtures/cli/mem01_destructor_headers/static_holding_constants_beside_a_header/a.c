#include <stdlib.h>
#include <stdio.h>
#include "conn.h"
static struct conn *log_target;
#define LOG_TARGET log_target
void log_reset(void) { log_target = NULL; }
static void h(struct conn *c) { c->list = 0; if (LOG_TARGET) puts(LOG_TARGET->ssl); }
void f(struct conn *c) { free(c->ssl); h(c); free(c); }
