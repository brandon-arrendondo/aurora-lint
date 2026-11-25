/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * Adding a sizeof to an integer is not pointer arithmetic, whatever the
 * operands are named: no operand has pointer type by its declaration.
 */

#include <stddef.h>

typedef unsigned long DWORD;

int options_length(int c, unsigned long ulOptions) {
  return c + ulOptions + (int)sizeof(DWORD);
}

size_t record_end(size_t record_start, size_t data_len) {
  size_t buf_end = record_start + sizeof(DWORD);
  buf_end += sizeof(DWORD);
  return buf_end + data_len;
}
