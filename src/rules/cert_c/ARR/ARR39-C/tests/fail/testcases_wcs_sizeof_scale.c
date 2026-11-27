/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR39-C violation
 * Settings: data_model=lp64, wchar_t_bits=32
 *
 * A wchar_t is as wide as the data model says: declared 4 bytes here, so
 * the pointer steps by 4 and a count scaled by sizeof(wchar_t) scales twice.
 */

/*
 * Rule: ARR39-C - Do not add or subtract a scaled integer to a pointer
 * Status: FAIL
 * Reason: Scaling wide string position by sizeof(wchar_t)
 */

#include <wchar.h>

void wcs_scale(void) {
    wchar_t buffer[100];
    wchar_t *pos;
    size_t len = 10;

    // Manually scaling position by sizeof(wchar_t)
    pos = buffer + (len * sizeof(wchar_t));  // Line 14 - VIOLATION
    *pos = L'X';
}

int main(void) {
    wcs_scale();
    return 0;
}
