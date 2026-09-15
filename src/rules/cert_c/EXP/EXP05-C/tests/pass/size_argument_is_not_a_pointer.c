/*
 * Rule: EXP05-C
 * Source: regression (mbedtls library/aes.c, library/bignum.c)
 * Status: PASS - Should NOT trigger EXP05-C violation
 *
 * A size argument is passed by value, so it can never cast const away --
 * not even when it really is const-qualified.
 */

#include <string.h>

static const int aes_test_ctr_len[3] = {16, 32, 36};
const size_t fixed_len = 8;

void copy(unsigned char *dst, const unsigned char *src) {
  int len = aes_test_ctr_len[0];

  memcpy(dst, src, len);
  memcpy(dst, src, fixed_len);
  memset(dst, 0, fixed_len);
}
