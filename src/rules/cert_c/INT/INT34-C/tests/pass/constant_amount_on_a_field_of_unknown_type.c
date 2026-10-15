/*
 * Rule: INT34-C
 * Status: PASS - a constant amount on an operand whose type is not known
 * Settings: data_model=lp64
 *
 * The struct's definition is in a header the scan does not have, so the
 * field may be 64 bits wide. Shifting it by 32 is not judged against a
 * 32-bit int the code never declared.
 */

#include "not_in_this_tree.h"

unsigned int high_half(struct digest_state *ctx)
{
    return (unsigned int)(ctx->bitlen >> 32);
}
