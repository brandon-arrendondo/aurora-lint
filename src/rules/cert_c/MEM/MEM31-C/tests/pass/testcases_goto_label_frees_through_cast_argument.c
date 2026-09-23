/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The goto-label free scan accepted only a bare identifier, field or
 * subscript as the freed argument, so a cleanup label that casts the
 * pointer on the way in -- hostap crypto_openssl.c's
 * `fail: crypto_ec_key_deinit((struct crypto_ec_key *) pkey);` -- credited
 * nothing, while the main walk's `strip_call_argument` had always looked
 * through the cast.
 */
#include <stdlib.h>

struct crypto_ec_key;
struct evp_pkey {
    int value;
};

static void crypto_ec_key_deinit(struct crypto_ec_key *key) {
    free(key);
}

struct crypto_ec_key *key_from_value(int n) {
    struct evp_pkey *pkey = malloc(sizeof(struct evp_pkey));
    if (!pkey) {
        return NULL;
    }
    if (n < 0) {
        goto fail;
    }
    pkey->value = n;
    return (struct crypto_ec_key *) pkey;
fail:
    crypto_ec_key_deinit((struct crypto_ec_key *) pkey);
    return NULL;
}
