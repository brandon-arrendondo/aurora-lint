/*
 * Rule: MEM31-C
 * Source: hostap src/crypto/tls_openssl.c, src/eap_peer/eap_sim.c,
 *         src/drivers/driver_wext.c; mosquitto src/net.c
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Four ways a branch's tail leaves the flow without its last statement
 * being a bare `return`. Each was hidden while "has a return anywhere
 * inside" decided the branch's fate, and surfaced as a double free the
 * moment the branch's own fall-through state was kept: the `return` is
 * the last statement of a chain-less `#ifdef`; it is the last statement
 * of one `#else` arm, whose state must not fold into the code below the
 * `#endif`; it is the tail of a `switch`'s last case; and it is a
 * `continue`, after which the rest of the loop body is not reached.
 */
#include <stdlib.h>

int check(void *p);
int failed(void);

int tail_under_ifdef(int use_blob, size_t len)
{
	if (use_blob) {
		void *bio = malloc(len);

		if (!bio)
			return -1;
#ifdef HAVE_PEM
		free(bio);
		return 0;
#endif
	}
	{
		void *bio = malloc(len);

		free(bio);
	}
	return 0;
}

void *else_arm_that_returns(int privacy, size_t len)
{
	void *data = malloc(len);

	if (!data)
		return NULL;
	if (privacy) {
#ifdef HAVE_RSA
		if (!check(data)) {
			free(data);
			return NULL;
		}
#else
		free(data);
		return NULL;
#endif
	}
	if (failed()) {
		free(data);
		return NULL;
	}
	return data;
}

int last_case_returns(int alg, size_t len)
{
	void *ext = malloc(len);
	int ret = 0;

	if (!ext)
		return -1;
	if (alg) {
		switch (alg) {
		case 1:
			ret = 1;
			break;
		default:
			free(ext);
			return -1;
		}
	}
	free(ext);
	return ret;
}

int continue_skips_the_rest_of_the_body(int n, size_t len)
{
	int i;

	for (i = 0; i < n; i++) {
		void *sock = malloc(len);

		if (!sock)
			return -1;
		if (failed()) {
			free(sock);
			if (i == 0)
				return -1;
			else
				continue;
		}
		free(sock);
	}
	return 0;
}
