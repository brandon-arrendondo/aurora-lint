/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A free in one arm of an #if/#elif/#else chain and a free in
 * another arm never compile into the same translation unit, so they are not
 * two frees on one path. The shape is hostap's crypto_openssl.c: the
 * OpenSSL-3 arm frees on its failure branch and returns, the legacy arm
 * jumps to an `err:` label that frees the same names -- names it declared
 * itself, in its own arm.
 */

#include <stdlib.h>

struct wpabuf;
struct wpabuf *wpabuf_alloc(size_t len);
void wpabuf_free(struct wpabuf *buf);
int keygen(void);

/* hostap crypto_openssl.c:1125 vs :1188 -- the free on the OpenSSL-3 arm's
 * failure branch and the free at the legacy arm's `err:` label. */
void *arm_free_then_other_arm_label_free(struct wpabuf **publ)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	struct wpabuf *pubkey = NULL;
	void *pkey = malloc(16);
	if (!pkey || !(pubkey = wpabuf_alloc(32)) || keygen() != 1) {
		wpabuf_free(pubkey);
		free(pkey);
		pkey = NULL;
	} else {
		*publ = pubkey;
	}
	return pkey;
#else
	struct wpabuf *pubkey = NULL;
	void *dh = malloc(16);
	if (!dh)
		goto err;
	pubkey = wpabuf_alloc(32);
	if (!pubkey)
		goto err;
	if (keygen() != 1)
		goto err;
	*publ = pubkey;
	return dh;

err:
	wpabuf_free(pubkey);
	free(dh);
	return NULL;
#endif
}

/* hostap crypto_openssl.c:4046 vs :4064 -- the same label name in two arms,
 * each freeing the pointer its own arm allocated. */
int same_label_in_two_arms(void)
{
	int ret = -1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	void *prime = malloc(32);
	if (!prime || keygen() != 1)
		goto fail;
	ret = 0;
fail:
	free(prime);
#else
	void *prime = malloc(32);
	if (!prime)
		goto fail;
	if (keygen() != 1)
		goto fail;
	ret = 0;
fail:
	free(prime);
#endif
	return ret;
}

/* A three-arm chain: each arm frees the pointer it allocated on its own
 * failure path and the walk must not carry the first arm's free into the
 * second, nor the second's into the third. */
void *three_arms(void)
{
	void *p = malloc(8);
	if (!p)
		return NULL;
#if defined(VARIANT_A)
	if (keygen() != 1) {
		free(p);
		return NULL;
	}
#elif defined(VARIANT_B)
	if (keygen() != 2) {
		free(p);
		return NULL;
	}
#else
	if (keygen() != 3) {
		free(p);
		return NULL;
	}
#endif
	return p;
}
