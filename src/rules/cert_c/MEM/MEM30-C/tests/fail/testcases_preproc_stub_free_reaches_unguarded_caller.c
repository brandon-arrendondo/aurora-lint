/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - the #else stub of init_ctx frees ctx, and run() is outside
 * any arm, so the configuration without REAL_BUILD compiles both: there,
 * run() passes the freed ctx on and frees it again
 */

#include <stdlib.h>

struct ctx { int a; };
struct handle { struct ctx *owner; };

#ifdef REAL_BUILD
static struct handle the_handle;
struct handle *init_ctx(struct ctx *ctx)
{
	the_handle.owner = ctx;
	return &the_handle;
}
#else
static inline struct handle *init_ctx(struct ctx *ctx)
{
	free(ctx);
	return (struct handle *) 1;
}
#endif

extern void *step_a(struct ctx *ctx);

int run(struct ctx *ctx)
{
	struct handle *h = init_ctx(ctx);
	if (h == 0)
		return -1;
	if (step_a(ctx) == 0) {
		free(ctx);
		return -1;
	}
	return 0;
}
