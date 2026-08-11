/*
 * Rule: API05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API05-C violation
 */

/*
 * Reason: SHA512_256_HASH_SIZE_WORDS is a #define macro constant, not a
 * later-declared parameter -- there is no such parameter to require
 * declaring first, so this is not a "declared after" ordering violation
 * (task 190; macro-opacity false positive found in curl's SHA-512 code).
 */

#define SHA512_256_HASH_SIZE_WORDS 8
typedef unsigned long uint64_t;

void hash_init(uint64_t H[SHA512_256_HASH_SIZE_WORDS])
{
    (void)H;
}
