struct inner { struct { char *ssl; char *raw; }; char *engine; };
struct conn { struct inner in; };
