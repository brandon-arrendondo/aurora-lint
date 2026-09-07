/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. A callee whose only
 * write through its output parameter is a FORWARDED call performs no direct
 * write, so the parameter never entered `modifies_params` and the coverage
 * walk that discharges forwarded-write obligations was never asked about it.
 * Both shapes here are curl's: a bare forward (`my_md5_init`) and a forward
 * whose argument is cast on the way (`randit`), which a bare-identifier match
 * could not see either (task 1027).
 */
#include <stdio.h>

struct ctx {
    unsigned long count;
};

/* The forwarded-to function writes through its parameter unconditionally,
   which is what discharges the obligation the forward parks. */
static void md5_init(struct ctx *c)
{
    c->count = 0;
}

static void my_md5_init(struct ctx *ctx)
{
    md5_init(ctx);
}

static void put_u32(unsigned char *out, unsigned int v)
{
    out[0] = (unsigned char)(v);
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}

/* Cast forward: `(unsigned char *)rnd` still forwards `rnd`. */
static void randit(unsigned int *rnd)
{
    put_u32((unsigned char *)rnd, 0x2400u);
}

void bare_forward_caller(void)
{
    struct ctx ctx;

    my_md5_init(&ctx);
    printf("%lu\n", ctx.count);
}

void cast_forward_caller(void)
{
    unsigned int r;

    randit(&r);
    printf("%u\n", r);
}
