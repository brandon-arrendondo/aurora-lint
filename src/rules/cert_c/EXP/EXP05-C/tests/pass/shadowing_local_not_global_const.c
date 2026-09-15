/*
 * Rule: EXP05-C
 * Source: regression (mbedtls library/aes.c)
 * Status: PASS - Should NOT trigger EXP05-C violation
 *
 * The locals are plain mutable buffers. Each file-scope const test vector
 * CONTAINS a local's name as a substring, which is what used to make the
 * local resolve as const-qualified.
 */

#include <string.h>

static const unsigned char aes_test_cfb128_iv[16] = {0};
static const unsigned char aes_test_cfb128_key[32] = {0};
static const unsigned char aes_test_ctr_nonce_counter[16] = {0};

int self_test(void) {
  unsigned char iv[16];
  unsigned char key[32];
  unsigned char nonce_counter[16];

  memset(key, 0, 32);
  memset(iv, 0, 16);
  memcpy(iv, aes_test_cfb128_iv, 16);
  memcpy(key, aes_test_cfb128_key, 32);
  memcpy(nonce_counter, aes_test_ctr_nonce_counter, 16);

  return iv[0] + key[0] + nonce_counter[0];
}
