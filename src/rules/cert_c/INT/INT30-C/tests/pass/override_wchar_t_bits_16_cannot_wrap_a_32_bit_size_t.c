/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - wchar_t is declared 16 bits
 * Settings: data_model=ilp32, wchar_t_bits=16
 *
 * A project built for 32-bit Windows declares wchar_t_bits = 16 (ilp32 says
 * nothing about wchar_t: it is a Linux and a Windows model alike). An int
 * count of at least 2 times a 2-byte wchar_t is at most 2^32 - 2 and cannot
 * wrap a 32-bit size_t.
 */

#include <stdlib.h>
#include <wchar.h>

wchar_t *wide_buffer(int size) {
    if (size <= 1) {
        return NULL;
    }
    return (wchar_t *)calloc(size, sizeof(wchar_t));
}
