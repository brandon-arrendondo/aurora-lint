// sqc-test: prescan
/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159) / task 401
 * Status: PASS - Should NOT trigger MEM30-C violation on 'ctx'
 *
 * Regression: mirrors hostap's wpas_group_formation_completed, which only
 * frees its first argument on a conditional error path (deep_free is only
 * reached when failure_reason is non-NULL). A cross-file FunctionSummary
 * saying a function MAY free a parameter under some code path must not be
 * trusted as though it ALWAYS frees it -- the caller below passes NULL for
 * failure_reason, taking the success path where ctx is never freed.
 */

#include <stdio.h>

struct ctx { int x; };

static void maybe_free(struct ctx *ctx, const char *failure_reason)
{
	if (failure_reason) {
		free(ctx);
		return;
	}
	ctx->x = 1;
}

void caller(struct ctx *ctx)
{
	maybe_free(ctx, NULL);
	printf("%d\n", ctx->x);
}
