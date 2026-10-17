struct conn { char *ssl; char *list; };
static struct conn *log_target;
static void set_log_target(struct conn *c) { log_target = c; }
