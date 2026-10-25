/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - a size shifted into an int
 *
 * A shift has the type of its left operand. len is a size_t, but 1 << len
 * is an int.
 */
#include <stdlib.h>

void *make_table(size_t len) {
    return malloc(1 << len);
}
