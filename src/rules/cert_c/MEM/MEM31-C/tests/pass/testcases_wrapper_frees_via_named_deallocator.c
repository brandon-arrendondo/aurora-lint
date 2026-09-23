/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * credit_frees_params() only recognized a literal `free(param)` call when
 * building a function's own summary - missing a call to another,
 * name-shaped deallocator (`ast_utils::is_deallocation_call_name`), such
 * as an external library's own `*_free` function whose body this checker
 * never sees (hostap's crypto_ec_key_deinit() calling OpenSSL's
 * EVP_PKEY_free() internally). crypto_ec_key_deinit()'s own summary must
 * still show it releases its parameter, or a project-local allocator
 * wrapper handed to it reads as a leak.
 */
#include <stdlib.h>

struct crypto_ec_key {
    int value;
};

/* Stands in for an external library function with no body in this repo. */
extern void EVP_PKEY_free(struct crypto_ec_key *key);

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
