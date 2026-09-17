/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Guards against overcrediting the macro-based wrapper fix: a macro that
 * does not itself release its argument must not be treated as freeing it,
 * so a caller relying on it still leaks.
 */
#include <stdlib.h>

#define LOG_PTR(p) do { (void)(p); } while (0)

struct ctx {
    int value;
};

static void inspect_ctx(struct ctx *ctx) {
    LOG_PTR(ctx);
}

void use_ctx(void) {
    struct ctx *ctx = malloc(sizeof(struct ctx));
    if (!ctx) {
        return;
    }
    inspect_ctx(ctx);
}
