/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - wchar_t is declared 32 bits on a 32-bit target
 * Settings: data_model=ilp32, wchar_t_bits=32
 *
 * With a 4-byte wchar_t, an int count of up to INT_MAX times sizeof(wchar_t)
 * reaches 2^33 - 4 and wraps a 32-bit size_t.
 */

#include <stdlib.h>
#include <wchar.h>

wchar_t *wide_buffer(int size) {
    if (size <= 1) {
        return NULL;
    }
    return (wchar_t *)calloc(size, sizeof(wchar_t)); /* VIOLATION */
}
