/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: mbedtls's destructor idiom, 47 false double frees on
 * onboarding. `gcm_free(ctx)` is named like a deallocator but its body
 * zeroizes the members and frees no pointer; `cipher_free(ctx)` frees a
 * FIELD off ctx and nothing else. Both bodies are in the scan, and a
 * summary that says "this callee does not release its parameter" must beat
 * the `*_free` name guess -- otherwise the `port_free(ctx)` that follows in
 * every `*_ctx_free` reads as a second free of ctx. `port_free` itself is
 * `#define port_free free`, so it is the literal free, not a guess.
 */

#include <stdlib.h>
#include <string.h>

#define port_free free

struct gcm_context {
    unsigned char key[32];
    int mode;
};

struct cipher_context {
    unsigned char *cipher_ctx;
    int mode;
};

static void zeroize(void *buf, size_t len) {
    volatile unsigned char *p = buf;
    while (len--) {
        *p++ = 0;
    }
}

void gcm_free(struct gcm_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    zeroize(ctx, sizeof(struct gcm_context));
}

void cipher_free(struct cipher_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    port_free(ctx->cipher_ctx);
    ctx->cipher_ctx = NULL;
}

static void gcm_ctx_free(void *ctx) {
    gcm_free(ctx);
    port_free(ctx);
}

static void cipher_ctx_free(void *ctx) {
    cipher_free(ctx);
    port_free(ctx);
}
