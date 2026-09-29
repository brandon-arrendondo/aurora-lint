/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `EVP_PKEY_free` has no body in the scan, so nothing shows
 * that it releases what it is handed. A name ending in `_free` is not
 * evidence of a free, so the block allocated in use_key() is reported
 * leaked. A project whose deallocator lives outside the scan declares it
 * (`[environment.deallocators]` in the manifest, or `--deallocator`), and
 * `--report-deallocator-candidates` lists the callees worth declaring.
 * Twin of the PASS fixture, where the callee's body frees.
 */
#include <stdlib.h>

struct crypto_ec_key {
    int value;
};

/* An external library function with no body in this scan. */
extern void EVP_PKEY_free(struct crypto_ec_key *key);

static void crypto_ec_key_deinit(struct crypto_ec_key *key) {
    EVP_PKEY_free(key);
}

static struct crypto_ec_key *crypto_ec_key_new(void) {
    return malloc(sizeof(struct crypto_ec_key));
}

void use_key(void) {
    /* VIOLATION: nothing shown to release `key` */
    struct crypto_ec_key *key = crypto_ec_key_new();
    if (!key) {
        return;
    }
    crypto_ec_key_deinit(key);
}
