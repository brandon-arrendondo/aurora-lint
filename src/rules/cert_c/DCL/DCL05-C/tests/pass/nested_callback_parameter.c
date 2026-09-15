/*
 * Rule: DCL05-C
 * Source: real-world (mbedtls library/pk_wrap.h vtable members, valkey
 *         src/valkeymodule.h ValkeyModule_BlockClient, task 1173)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * A function pointer whose own parameter list holds another function pointer
 * is still a function pointer type, which CERT exempts; the nesting is in the
 * parameter list and reads left to right, not inside-out.
 */

#include <stddef.h>

struct pk_info {
    int (*sign_func)(void *pk, const unsigned char *hash, size_t hash_len,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
};

extern void *(*block_client)(void *ctx, void (*free_privdata)(void *, void *), long long ms);

void run_with(void (*cb)(void (*inner)(int), int));
