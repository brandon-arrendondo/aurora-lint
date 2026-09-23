/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: a readable body still refutes its name. mbedtls's
 * `mbedtls_gcm_free(ctx)` zeroizes the context's members and releases
 * nothing it was handed; every call in its body goes to a plain name, so
 * the body was read all the way through and its empty free sets are a
 * measurement, not a gap. That still refutes the `*_free` name, and the
 * read below is a read of live memory.
 *
 * Only a body that stops being readable -- at a call through a function
 * pointer -- falls back to the name.
 */

#include <stdlib.h>
#include <string.h>

struct gcm_context {
    unsigned char buf[16];
    int initialized;
};

void gcm_ctx_free(struct gcm_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->initialized = 0;
}

int reads_a_zeroized_context(void)
{
    struct gcm_context *ctx = malloc(sizeof(struct gcm_context));

    if (ctx == NULL) {
        return 1;
    }
    ctx->initialized = 1;
    gcm_ctx_free(ctx);

    /* COMPLIANT: gcm_ctx_free zeroizes members; ctx itself is still live */
    return ctx->initialized;
}
