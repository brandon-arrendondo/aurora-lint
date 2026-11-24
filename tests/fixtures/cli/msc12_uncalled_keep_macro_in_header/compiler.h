#define INIT_FN __attribute__((constructor))
#define KEEP_SYM __attribute__((__used__))
#define MY_CTOR_PRIO(p) __attribute__((constructor(p)))
#define USED_FOR_ASSERTS_ONLY __attribute__((unused))
