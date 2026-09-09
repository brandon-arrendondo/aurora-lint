/*
 * Rule: INT30-C
 * Source: task 916
 * Status: PASS - a product computed in size_t cannot wrap 64 bits
 *
 * A 32-bit-or-narrower count times a small compile-time sizeof is performed in
 * size_t. Asking whether the product fits in 32 bits is the wrong question for
 * size_t arithmetic, and answering it was this rule's word-width blindness.
 */

#include <stdlib.h>

void *alloc_rows(const char *text) {
    unsigned int count = (unsigned int)atoi(text);
    size_t bytes = count * sizeof(long);
    return malloc(bytes);
}
