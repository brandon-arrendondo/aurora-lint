/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int size after an alignment computed from sizeof
 *
 * aligned_alloc takes the alignment and then the size. The alignment,
 * sizeof(void *) * 2, is a size_t, but len, the size, is held in an int.
 */
#include <stdlib.h>

int block_bytes(void);

void *make_block(void) {
    int len = block_bytes();
    return aligned_alloc(sizeof(void *) * 2, len);
}
