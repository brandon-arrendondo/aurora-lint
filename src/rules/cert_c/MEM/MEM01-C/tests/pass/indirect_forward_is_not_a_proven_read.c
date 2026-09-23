/*
 * Rule: MEM01-C
 * Source: custom (hostap driver-ops shape, via EXP33-C)
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: `reinit` dereferences its `pbuf` parameter and also forwards
 * it to a call through `ctx->driver->refill`, a struct-of-function-pointers
 * dispatch nothing here can resolve to a definition. Before an earlier
 * fix, build_read_only_params tested `dereferences_params -
 * modifies_params` only -- the pre-1437/1442 shape of EXP33-C's own
 * build_read_only_deref_fns -- so `pbuf` came back PROVEN read-only, and
 * `reinit(ctx, &buf)` after the free was read as a genuine use of the freed
 * pointer rather than a possible reassignment.
 *
 * It is neither proven: the indirect callee may well store a fresh block
 * through `pbuf`, and no analysis here can say. The honest answer is
 * unknown, which for this rule means withhold (ADR-0001).
 */

#include <stdlib.h>

struct driver_ops {
    int (*refill)(void *priv, char **pbuf);
};

struct driver_ctx {
    struct driver_ops *driver;
    void *priv;
};

static int reinit(struct driver_ctx *ctx, char **pbuf)
{
    if (*pbuf == NULL) {
        return -1;
    }
    if (ctx->driver == NULL || ctx->driver->refill == NULL) {
        return -1;
    }
    return ctx->driver->refill(ctx->priv, pbuf);
}

void use_buffer(struct driver_ctx *ctx)
{
    char *buf = malloc(64);

    if (buf == NULL) {
        return;
    }
    free(buf);
    reinit(ctx, &buf);
}
