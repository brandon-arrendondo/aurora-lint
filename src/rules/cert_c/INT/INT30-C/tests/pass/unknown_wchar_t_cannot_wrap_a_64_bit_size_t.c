/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - wchar_t is not declared, and size_t is 64 bits
 * Settings: data_model=lp64
 *
 * lp64 says nothing about wchar_t, so its size is unknown. It is still an
 * integer type, no wider than the widest the facts declare (8 bytes), so an
 * int count times it is at most 2^34 and cannot wrap a 64-bit size_t: nothing
 * is reported on a guessed width.
 */

#include <stdlib.h>
#include <wchar.h>

wchar_t *wide_buffer(int size) {
    if (size <= 1) {
        return NULL;
    }
    return (wchar_t *)calloc(size, sizeof(wchar_t));
}
