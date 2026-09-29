/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - `ptrdiff_t` against a narrower `unsigned int`
 * Settings: data_model=lp64
 *
 * `ptrdiff_t` is a 64-bit signed type on LP64, the declared model, which can
 * represent every `unsigned int` value, so the unsigned operand converts to it
 * and the comparison keeps its sign.
 */

#include <stddef.h>

int within(ptrdiff_t offset, unsigned int limit)
{
    return offset < limit;
}
