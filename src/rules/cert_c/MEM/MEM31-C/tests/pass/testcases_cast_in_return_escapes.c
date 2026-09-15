/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: `return (T *) p;` hands the block to the caller exactly as
 * `return p;` does; so do `return (p);` and `return ok ? p : NULL;`. hostap
 * spells every `crypto_ec_key *` return with a cast (crypto_openssl.c:3287
 * and siblings).
 */

#include <stdlib.h>

struct k;
int setup(void *p);

struct k *return_with_cast(void)
{
	void *pkey = NULL;
	void *pub = malloc(8);
	if (!pub)
		goto fail;
	pkey = malloc(8);
	if (!pkey || setup(pkey) != 1)
		goto fail;
	free(pub);
	return (struct k *) pkey;
fail:
	free(pkey);
	free(pub);
	return NULL;
}

void *return_parenthesized(void)
{
	void *p = malloc(8);
	if (!p)
		return NULL;
	return (p);
}

void *return_conditional(int ok)
{
	void *p = malloc(8);
	if (!p)
		return NULL;
	if (!ok) {
		free(p);
		return NULL;
	}
	return ok ? p : NULL;
}
