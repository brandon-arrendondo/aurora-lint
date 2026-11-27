/*
 * Rule: ARR39-C
 * Source: synthetic
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * How wide a wchar_t is, the data model does not say unless wchar_t_bits
 * is declared, and ISO C lets it be a single byte. With the width unknown
 * the pointer is not known to step by more than one byte, so no finding is
 * made. fail/testcases_wcs_sizeof_scale.c declares the width.
 */

#include <wchar.h>

void wcs_scale(void) {
    wchar_t buffer[100];
    wchar_t *pos;
    size_t len = 10;

    pos = buffer + (len * sizeof(wchar_t));
    *pos = L'X';
}
