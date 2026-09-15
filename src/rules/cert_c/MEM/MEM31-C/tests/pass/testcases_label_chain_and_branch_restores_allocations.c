/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: Two shapes hostap's crypto_openssl.c writes. A cleanup label whose
 * block ends in `goto out;` reaches `out:`'s frees on every entry, so a jump
 * to `fail:` frees what `out:` frees. And a branch that nulls the container
 * and leaves (`ctx = NULL; goto fail;`) does not change what the
 * fall-through path holds: `return ctx` below it still hands the caller
 * `ctx` and the field allocated under it.
 */

#include <stdlib.h>

struct crypto_hash { void *ctx; };
int setup(void *p);

/* crypto_openssl.c:3226-3238: fail: frees pkey, then jumps to out:, which
 * frees pub. A goto to fail therefore leaks neither. */
void *label_block_ends_in_goto(void)
{
	void *pkey = NULL;
	void *pub = malloc(8);
	if (!pub)
		return NULL;
	pkey = malloc(8);
	if (!pkey || setup(pkey) != 1)
		goto fail;
out:
	free(pub);
	return pkey;
fail:
	free(pkey);
	pkey = NULL;
	goto out;
}

/* crypto_openssl.c:1432-1455: the failure branch frees the container,
 * nulls it and jumps to the label; the success path returns it. */
struct crypto_hash *null_then_goto_keeps_container_on_fallthrough(void)
{
	struct crypto_hash *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;
	ctx->ctx = malloc(16);
	if (!ctx->ctx) {
		free(ctx);
		ctx = NULL;
		goto fail;
	}
	if (setup(ctx->ctx) != 1) {
		free(ctx->ctx);
		free(ctx);
		ctx = NULL;
		goto fail;
	}
fail:
	return ctx;
}
