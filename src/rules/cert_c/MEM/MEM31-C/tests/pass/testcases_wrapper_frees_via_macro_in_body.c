/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * credit_frees_params() only recognized a literal `free(param)` call when
 * building a function's own summary, missing a function-like macro that
 * frees its argument (task 1236). deinit_ctx() frees its own parameter
 * only through SAFE_FREE(), a macro - not literally `free` - so its
 * summary must still show it releases `ctx`, or every caller that
 * allocates and passes it through deinit_ctx() reads as a leak.
 */
#include <stdlib.h>

#define SAFE_FREE(p) free(p)

struct ctx {
    int value;
};

static void deinit_ctx(struct ctx *ctx) {
    SAFE_FREE(ctx);
}

void use_ctx(void) {
    struct ctx *ctx = malloc(sizeof(struct ctx));
    if (!ctx) {
        return;
    }
    deinit_ctx(ctx);
}
