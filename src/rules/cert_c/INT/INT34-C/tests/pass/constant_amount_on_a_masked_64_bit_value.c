/*
 * Rule: INT34-C
 * Status: PASS - a mask's result has the type of its 64-bit operands
 *
 * `x & 0xFF00000000000000ULL` is a uint64_t, so shifting it by 56 is in
 * range on every implementation.
 */

#include <stdint.h>

uint64_t top_byte(uint64_t x)
{
    return (x & 0xFF00000000000000ULL) >> 56;
}
