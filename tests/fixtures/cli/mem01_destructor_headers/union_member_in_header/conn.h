struct conn { union { char *ssl; char *raw; } u; char *engine; };
