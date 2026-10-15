union payload { char *ssl; char *raw; };
typedef struct conn { union payload u; char *engine; } conn_t;
