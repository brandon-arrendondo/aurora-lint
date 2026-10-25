/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int size after a size_t alignment
 *
 * aligned_alloc takes the alignment and then the size. align is a size_t,
 * but len, the size, is held in an int.
 */
#include <stdlib.h>

int block_bytes(void);

void *make_block(size_t align) {
    int len = block_bytes();
    return aligned_alloc(align, len);
}
