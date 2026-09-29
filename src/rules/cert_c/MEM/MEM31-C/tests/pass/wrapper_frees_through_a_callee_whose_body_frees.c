/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A wrapper's summary shows it releasing its parameter when the body hands
 * that parameter to a callee whose own body frees it (hostap's
 * crypto_ec_key_deinit() calling EVP_PKEY_free()). The free is carried
 * outward through the call chain from the callee's body, so a project-local
 * allocation handed to the wrapper is not a leak. The callee's name has
 * nothing to do with it: the twin FAIL fixture, where EVP_PKEY_free has no
 * body in the scan, reports the leak.
 */
#include <stdlib.h>

struct crypto_ec_key {
    int value;
};

/* Stands in for the library function, with a body the scan can read. */
void EVP_PKEY_free(struct crypto_ec_key *key) {
    free(key);
}

static void crypto_ec_key_deinit(struct crypto_ec_key *key) {
    EVP_PKEY_free(key);
}

static struct crypto_ec_key *crypto_ec_key_new(void) {
    return malloc(sizeof(struct crypto_ec_key));
}

void use_key(void) {
    struct crypto_ec_key *key = crypto_ec_key_new();
    if (!key) {
        return;
    }
    crypto_ec_key_deinit(key);
}
