/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - An assertion over casts to standard integer typedefs
 * Expect: count=3
 *
 * `size_t` and `uint8_t` are integer types, so a cast to one belongs in
 * an integer constant expression (C11 6.6p6), as it does in the system
 * header's `CMSG_ALIGN`. A static assertion could test each condition.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

void check(void)
{
    assert((size_t) ~(sizeof(size_t) - 1) != 0);
    assert((uint8_t)300 == 44);
    assert((uint32_t)1 << 31 > 0);
}
