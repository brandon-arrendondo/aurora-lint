/*
 * Rule: INT30-C
 * Source: task 916
 * Status: FAIL - a range entirely below zero wraps at any width
 *
 * Guards the definite-underflow channel at 64-bit widths. Answering "does this
 * definitely wrap" only for widths under 64 left size_t arithmetic with no
 * definite-underflow detection at all, which reads as "proven safe".
 */

#include <stddef.h>

size_t below_zero(void) {
    size_t zero = 0;
    return zero - 1;
}
