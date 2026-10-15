struct conn { char *ssl; char *list; unsigned flags; };
#define CONN_CLOSED 0x2u
#define CONN_RESET_FLAGS (CONN_CLOSED | 0x10u)
