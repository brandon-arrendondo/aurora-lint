/*
 * Rule: INT34-C
 * Status: PASS - an amount that is constant but cannot be folded
 *
 * `HEADER_SHIFT` comes from a header the scan does not have, so its value is
 * unknown. A constant that cannot be read is not judged.
 */

#include "not_in_this_tree.h"

unsigned int shift_by_header_constant(unsigned int x)
{
    return x >> HEADER_SHIFT;
}
