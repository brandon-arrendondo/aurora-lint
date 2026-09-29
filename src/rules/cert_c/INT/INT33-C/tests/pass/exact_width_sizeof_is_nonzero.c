/*
 * Rule: INT33-C
 * Source: regression
 * Status: PASS - under the default ISO data model
 *
 * ISO C does not fix sizeof(uint64_t), since CHAR_BIT may exceed 8, but an
 * exact-width type has exactly 64 bits and no padding over a char of at least
 * 8 bits, so its size is between 1 and 8 and the divisor is at least 8.
 */
#include <stdint.h>

unsigned bit_index(unsigned id) {
  return id % (sizeof(uint64_t) * 8);
}

unsigned word_index(unsigned id) {
  return id / (sizeof(uint32_t) * 8);
}
