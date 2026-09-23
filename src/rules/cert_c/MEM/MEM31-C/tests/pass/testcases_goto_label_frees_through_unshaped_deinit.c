/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The goto-label free scan (collect_frees_in_label) gated on the callee's
 * NAME before consulting its summary, so a cleanup label that releases
 * through a function the prescan saw free its parameter -- but whose name
 * has no deallocator shape, hostap's crypto_ec_key_deinit()/tls_deinit() --
 * credited nothing, and every `goto fail` read as a leak. The main walk
 * already credited the same call on its summary alone (the
 * sibling gap in credit_frees_params was an earlier fix).
 */
#include <stdlib.h>

struct crypto_ec_key {
    int value;
};

static void crypto_ec_key_deinit(struct crypto_ec_key *key) {
    free(key);
}

int use_key(int n) {
    struct crypto_ec_key *key = malloc(sizeof(struct crypto_ec_key));
    if (!key) {
        return -1;
    }
    if (n < 0) {
        goto fail;
    }
    key->value = n;
    crypto_ec_key_deinit(key);
    return 0;
fail:
    crypto_ec_key_deinit(key);
    return -1;
}
