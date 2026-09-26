/*
 * Rule: MEM30-C
 * Source: testcases (shape of hostap wpa_supplicant/eapol_test.c)
 * Status: EXPECTED FAIL - Known limitation, in the OPPOSITE direction from
 * most expected_fail fixtures: MEM30-C currently REPORTS this file and the
 * correct result is NO violation. It sits here, ignored, until the tool can
 * see why.
 *
 * init_ctx's #else stub frees ctx, and run() sits outside any arm, so on the
 * face of it the configuration without REAL_BUILD compiles both (the
 * matching fail fixture). But run() also reads cfg->method, a member struct
 * config only has under #ifdef REAL_BUILD: without REAL_BUILD this file does
 * not compile, so no configuration pairs run() with the stub, and nothing
 * here is freed twice. Seeing that needs the file's unconditional use of a
 * conditionally-declared struct member to count as proof that REAL_BUILD is
 * defined for it.
 */

#include <stdlib.h>

struct ctx { int a; };
struct handle { struct ctx *owner; };

struct config {
	int id;
#ifdef REAL_BUILD
	int method;
#endif
};

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

extern void *step_a(struct ctx *ctx, int method);

int run(struct ctx *ctx, struct config *cfg)
{
	struct handle *h = init_ctx(ctx);
	if (h == 0)
		return -1;
	if (step_a(ctx, cfg->method) == 0) {
		free(ctx);
		return -1;
	}
	return 0;
}
