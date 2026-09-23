/*
 * Rule: MEM30-C
 * Source: valkey src/cluster.c migrateCommand(), src/modules/lua/debug_lua.c
 *         ldbCatStackValueRec(), hostap src/crypto/crypto_wolfssl.c
 *         dh5_init(), mosquitto lib/net_mosq_ocsp.c (task 1360)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Two walk defects. A label whose predecessor in the flow is a `return`
 * is reached only by `goto`, and the walk resets its state there -- but a
 * comment between the two is a named sibling too, and the reset looked
 * only at the immediately preceding one. And an alias `old_s -> s`
 * recorded at `old_s = s` survived `s = create()`, so freeing `old_s`
 * freed the fresh `s` as well; a variable given a new value aliases
 * nothing it did before, and nothing that aliased it refers to what it
 * now holds.
 */
#include <stdlib.h>

int fail(void);
int retry_ok(void);
void *create(void);
int use(void *p);

void label_after_a_comment(void)
{
	void *ov = malloc(8), *kv = malloc(8);
	int may_retry = 1;

try_again:
	if (fail())
		goto socket_err;
	free(ov);
	free(kv);
	return;

	/* On socket errors we try to close the cached socket and try again.
	 * It is very common for the cached socket to get closed. */
socket_err:
	if (retry_ok() && may_retry) {
		may_retry = 0;
		goto try_again;
	}
	free(ov);
	free(kv);
}

int label_after_a_trailing_comment(void *br)
{
	if (fail())
		goto end;
	free(br);
	return 1; /* OK */
end:
	free(br);
	return 0; /* Not OK */
}

void *old_value_kept_then_freed(void *s)
{
	void *old_s = s;

	s = create();
	free(old_s);
	return s;
}

void *result_handed_over_then_the_handle_nulled(void)
{
	void *dh = malloc(8);
	void *ret = NULL;

	if (!dh)
		return NULL;
	if (use(dh) != 0)
		goto done;
	ret = dh;
	dh = NULL;
done:
	if (dh)
		free(dh);
	return ret;
}
