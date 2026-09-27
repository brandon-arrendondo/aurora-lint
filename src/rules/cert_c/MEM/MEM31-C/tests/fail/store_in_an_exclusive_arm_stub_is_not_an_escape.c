/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: run() is compiled only with REAL_BUILD, where
 * ctx_register() reads the context and keeps nothing, so the block run()
 * allocates is leaked. The ctx_register() that links its argument into the
 * registry is the #else stub, which never meets run(). Crediting the stub's
 * store at every call hid the leak.
 */

#include <stdlib.h>

struct ctx {
    int id;
};

static struct ctx *registry;
int log_id(int id);

#if defined(REAL_BUILD)
void ctx_register(struct ctx *c)
{
    log_id(c->id);
}
#else
void ctx_register(struct ctx *c)
{
    registry = c;
}
#endif

#if defined(REAL_BUILD)
void run(void)
{
    struct ctx *c = malloc(sizeof *c);
    if (c == NULL)
        return;
    c->id = 1;
    ctx_register(c);
}
#endif
