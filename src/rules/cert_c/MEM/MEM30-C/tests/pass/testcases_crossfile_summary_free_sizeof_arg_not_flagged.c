// sqc-test: prescan
/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 wave 30) / task 400
 * Status: PASS - Should NOT trigger MEM30-C violation on 'ctx'
 *
 * Regression: mirrors hostap's bin_clear_free(ctx, sizeof(*ctx)). `sizeof`'s
 * operand is never evaluated in C, so `sizeof(*ctx)` sitting alongside the
 * freed argument `ctx` in the same call is not a dereference of freed
 * memory and must not be flagged.
 */

struct ctx_t { int x; };

static void bin_clear_free(struct ctx_t *ctx, unsigned long sz)
{
	free(ctx);
}

void caller(struct ctx_t *ctx)
{
	bin_clear_free(ctx, sizeof(*ctx));
}
