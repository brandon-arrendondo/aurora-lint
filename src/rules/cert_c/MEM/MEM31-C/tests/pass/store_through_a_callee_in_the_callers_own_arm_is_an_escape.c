/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: run() is compiled only with REAL_BUILD, where
 * ctx_register() hands its argument to keep(), which links it into the
 * registry, so the block run() allocates is not leaked. The #else stub
 * stores its argument directly; that it does so must not hide the store
 * the REAL_BUILD definition makes through a callee.
 */

#include <stdlib.h>

struct ctx {
    int id;
};

static struct ctx *registry, *other;

void keep(struct ctx *c)
{
    registry = c;
}

#if defined(REAL_BUILD)
void ctx_register(struct ctx *c)
{
    keep(c);
}
#else
void ctx_register(struct ctx *c)
{
    other = c;
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
