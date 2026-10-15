/*
 * Rule: INT34-C
 * Status: FAIL - masking a uint32_t keeps it 32 bits wide
 *
 * `x & 0xFFu` is still a 32-bit unsigned value, so shifting it by 32 is
 * undefined behaviour.
 */

#include <stdint.h>

uint64_t widen_late(uint32_t x)
{
    return (x & 0xFFu) << 32;
}
