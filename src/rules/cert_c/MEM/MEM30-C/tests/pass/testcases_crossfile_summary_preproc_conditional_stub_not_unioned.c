/*
 * Rule: MEM30-C
 * Source: hostap wpa_supplicant/eapol_test.c + src/eapol_supp/eapol_supp_sm.h
 *
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
 *
 * The caller sits inside `#if defined(REAL_BUILD) && ...`, as hostap's
 * rsn_supp/preauth.c does, and the freeing stub is the `#else` of
 * REAL_BUILD: the two never compile together, so the stub's free does not
 * apply to this call (ADR-0010 D4). A caller outside any arm is paired with
 * both bodies, and in the configuration that compiles the stub its use of
 * ctx is a real use after free (see the matching fail fixture).
 */

#include <stdlib.h>

struct ctx { int a; int b; int c; };

#ifdef REAL_BUILD
struct handle { struct ctx *owner; };
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
extern void *step_b(struct ctx *ctx);

#if defined(REAL_BUILD) && !defined(NO_STEPS)
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
#endif
