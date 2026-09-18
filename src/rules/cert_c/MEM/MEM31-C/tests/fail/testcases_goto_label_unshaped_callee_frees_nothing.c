/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Guards the label-scan fix (task 1241) from over-crediting: a callee with
 * no deallocator shape in its name is credited at a cleanup label only
 * when its summary shows it releases the parameter. One that merely reads
 * the object frees nothing, so the `goto fail` path still leaks.
 */
#include <stdlib.h>

struct crypto_ec_key {
    int value;
};

static int crypto_ec_key_inspect(struct crypto_ec_key *key) {
    return key->value;
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
    free(key);
    return 0;
fail:
    (void)crypto_ec_key_inspect(key);
    return -1;
}
