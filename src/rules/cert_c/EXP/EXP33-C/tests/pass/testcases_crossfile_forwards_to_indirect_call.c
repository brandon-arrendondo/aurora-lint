/*
 * Rule: EXP33-C
 * Source: testcases (hostap accounting.c/ap_drv_ops.h shape)
 * Status: PASS - Should NOT trigger EXP33-C violation (aurora_lint 1442).
 * `wrapper` forwards `data` to a call through `driver->read_sta_data`, a
 * struct-of-function-pointers dispatch this build can never resolve to a
 * concrete definition -- the field name has no relationship to any global
 * function of the same name (same C-semantics test the call graph already
 * uses to avoid fabricating an edge under that name, task 562). `relay`
 * then forwards its own `data` param to `wrapper` and directly dereferences
 * it, which is what put `relay` in `dereferences_params` and made it look
 * read-only before this fix -- `wrapper` never gets a chance to prove it
 * writes `data`, because nothing can prove what the indirect call does, so
 * the honest answer is "unknown", not "read-only". Companion to
 * fail/testcases_crossfile_readonly_deref.c, which has no forwarding (nor
 * indirection) at all and must stay flagged.
 */

struct driver_ops {
    int (*read_sta_data)(void *priv, struct sta_driver_data *data);
};

struct driver_ctx {
    struct driver_ops *driver;
    void *priv;
};

static int wrapper(struct driver_ctx *ctx, struct sta_driver_data *data) {
    if (ctx->driver == 0 || ctx->driver->read_sta_data == 0)
        return -1;
    return ctx->driver->read_sta_data(ctx->priv, data);
}

int relay(struct driver_ctx *ctx, struct sta_driver_data *data) {
    if (wrapper(ctx, data))
        return -1;
    return data->rx_bytes;
}

void f(struct driver_ctx *ctx) {
    struct sta_driver_data data;
    relay(ctx, &data);
}
