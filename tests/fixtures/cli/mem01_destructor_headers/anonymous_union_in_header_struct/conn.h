struct inner { union { char *ssl; char *raw; }; char *engine; };
struct conn { struct inner in; };
