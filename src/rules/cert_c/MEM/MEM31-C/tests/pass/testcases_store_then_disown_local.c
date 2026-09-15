/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: Storing a block somewhere that outlives the function and then
 * nulling the local -- `field = p; p = NULL;` -- transfers ownership; the
 * local no longer holds anything to leak. Re-using the local for a second
 * allocation afterwards starts a new block the function does own, which is
 * freed below. The shape is mbedtls ssl_tls.c's `peer_cert = chain;
 * chain = NULL;`.
 */

#include <stdlib.h>

struct sess { void *peer_cert; };
struct ssl { struct sess *session_negotiate; };
int parse(void *p);

int store_then_null(struct ssl *ssl)
{
	void *chain = calloc(1, 16);
	if (chain == NULL)
		return -1;
	ssl->session_negotiate->peer_cert = chain;
	chain = NULL;
	return 0;
}

int store_then_null_then_cleanup_label(struct ssl *ssl)
{
	int ret;
	void *chain = calloc(1, 16);
	if (chain == NULL)
		return -1;
	ret = parse(chain);
	if (ret != 0)
		goto exit;
	ssl->session_negotiate->peer_cert = chain;
	chain = NULL;
exit:
	if (chain != NULL)
		free(chain);
	return ret;
}

int store_then_reallocate_the_name(struct ssl *ssl, void **out)
{
	void *p = calloc(1, 16);
	if (p == NULL)
		return -1;
	*out = p;
	p = calloc(1, 32);
	if (p == NULL)
		return -1;
	ssl->session_negotiate->peer_cert = p;
	return 0;
}
