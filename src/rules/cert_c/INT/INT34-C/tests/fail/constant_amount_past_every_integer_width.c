/*
 * Rule: INT34-C
 * Status: FAIL - an amount of 64 on an operand whose type is not known
 *
 * The field's type is in a header the scan does not have, but no standard
 * integer type is wider than 64 bits, so shifting it by 64 is undefined
 * whatever that type is.
 */

#include "not_in_this_tree.h"

unsigned long long past_the_end(struct digest_state *ctx)
{
    return ctx->bitlen >> 64;
}
