/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - a key length typed unsigned int
 *
 * keylen ends with the size word len: the length of the key buffer, held
 * in an unsigned int rather than a size_t.
 */
int decrypt_block(unsigned char iv[16], unsigned int keylen);
