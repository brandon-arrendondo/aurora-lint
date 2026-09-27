/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: run() is compiled only with REAL_BUILD, where ctx_free()
 * logs the context and releases nothing, so the block run() allocates is
 * leaked. The ctx_free() that frees its argument is the #else stub, which
 * never meets run(). Its free is not evidence for a call it cannot link
 * with, whatever the callee is called.
 */

#include <stdlib.h>

struct ctx {
    int id;
};

int log_id(int id);

#if defined(REAL_BUILD)
void ctx_free(struct ctx *c)
{
    log_id(c->id);
}
#else
void ctx_free(struct ctx *c)
{
    free(c);
}
#endif

#if defined(REAL_BUILD)
void run(void)
{
    struct ctx *c = malloc(sizeof *c);
    if (c == NULL)
        return;
    c->id = 1;
    ctx_free(c);
}
#endif
