/*
 * Rule: INT34-C
 * Status: PASS - a 128-bit extended integer shifted by 64
 * Settings: data_model=lp64
 *
 * `__uint128_t` is 128 bits wide where it exists, so taking the high half of
 * a full product is in range. The other factor converts to it whatever its
 * own type, here one from a header the scan does not have.
 */

#include <stdint.h>
#include "not_in_this_tree.h"

uint64_t high_product(uint64_t a, hdr_u64 b)
{
    return ((__uint128_t)a * b) >> 64;
}
