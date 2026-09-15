/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * `g_ctx = c` makes the two names share a block, and the alias credit that
 * keeps `c` from reading as leaked must not also turn the second release
 * into a double free. The guard that decides which name owns what --
 * `c != g_ctx` -- is exactly what this path-insensitive walk cannot read, so
 * an inherited freed mark is not evidence that the two spellings denote the
 * same block HERE.
 */

#include <stdlib.h>

struct ctx {
    int refs;
};

static struct ctx *g_ctx;

static struct ctx *ctx_new(void) {
    return malloc(sizeof(struct ctx));
}

static void ctx_free(struct ctx *c) {
    free(c);
}

int ctx_init(int refs) {
    struct ctx *c;

    c = ctx_new();
    if (c == NULL) {
        return -1;
    }
    if (refs == 0) {
        g_ctx = c;
    }

    if (c != g_ctx) {
        ctx_free(c);
    }
    if (refs == 0) {
        ctx_free(g_ctx);
        g_ctx = NULL;
    }
    return 0;
}
