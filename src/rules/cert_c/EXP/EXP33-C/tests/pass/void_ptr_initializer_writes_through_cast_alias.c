/*
 * Description: a void * initializer that casts its parameter into a local and
 * writes the fields through it initializes the caller's object
 *
 * The hash-context initializer shape: the callee writes every field it
 * owns through the cast alias and reads none, so the caller's context is
 * initialized when the call returns.
 */
struct ctx {
    unsigned long h[2];
    unsigned long count;
};

static int ctx_init(void *context)
{
    struct ctx *const c = (struct ctx *)context;
    c->h[0] = 1UL;
    c->h[1] = 2UL;
    c->count = 0UL;
    return 0;
}

unsigned long caller(void)
{
    struct ctx c;
    ctx_init(&c);
    return c.count;
}
