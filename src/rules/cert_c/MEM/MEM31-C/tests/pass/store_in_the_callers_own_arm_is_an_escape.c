/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: run() is compiled only with REAL_BUILD, and that build's
 * ctx_register() links its argument into the registry, so the block run()
 * allocates is not leaked. The #else stub, which keeps nothing, never meets
 * run().
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
    registry = c;
}
#else
void ctx_register(struct ctx *c)
{
    log_id(c->id);
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
