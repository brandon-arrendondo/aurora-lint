struct conn { char *ssl; char *engine; };
extern struct conn *log_conn;
#define LOG_TARGET log_conn
