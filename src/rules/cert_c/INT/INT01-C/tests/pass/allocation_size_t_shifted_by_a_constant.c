/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - a size_t shifted by a constant
 *
 * A shift has the type of its left operand, so len << 1 is a size_t.
 */
#include <stdlib.h>

void *make_table(size_t len) {
    return malloc(len << 1);
}
