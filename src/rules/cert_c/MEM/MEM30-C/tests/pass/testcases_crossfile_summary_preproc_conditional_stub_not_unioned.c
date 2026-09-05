// sqc-test: prescan
/*
 * Rule: MEM30-C
 * Source: hostap wpa_supplicant/eapol_test.c + src/eapol_supp/eapol_supp_sm.h
 *         (task 654)
 * Status: PASS - Should NOT trigger MEM30-C violation on 'ctx'
 *
 * hostap's eapol_supp_sm.h declares the real eapol_sm_init() under
 * `#if IEEE8021X_EAPOL` but also provides a `#else`-guarded stub with the
 * same name that unconditionally frees its argument (a "feature compiled
 * out" no-op). aurora-lint has no preprocessor, so both bodies get parsed and their
 * free-related facts were being unioned into one cross-file FunctionSummary
 * -- crediting the REAL init_ctx() (which never frees its argument) with
 * "unconditionally frees param 0" purely because of the unrelated,
 * mutually-exclusive stub. That poisoned the caller's 'ctx' as already-freed
 * before any of its three independent, mutually-exclusive
 * `if (...) { free(ctx); return -1; }` early-return checks even ran, so
 * each one's own real free was flagged as a double-free against the
 * others -- not an actual double-free.
 */

#include <stdlib.h>

struct ctx { int a; int b; int c; };

#ifdef REAL_BUILD
struct handle *init_ctx(struct ctx *ctx);
#else
static inline struct handle *init_ctx(struct ctx *ctx)
{
	free(ctx);
	return (struct handle *) 1;
}
#endif

extern void *step_a(struct ctx *ctx);
extern void *step_b(struct ctx *ctx);

int run(struct ctx *ctx)
{
	struct handle *h;
	void *a, *b;

	h = (struct handle *) init_ctx(ctx);
	if (h == 0) {
		free(ctx);
		return -1;
	}

	a = step_a(ctx);
	if (a == 0) {
		free(ctx);
		return -1;
	}

	b = step_b(ctx);
	if (b == 0) {
		free(ctx);
		free(a);
		return -1;
	}

	return 0;
}
