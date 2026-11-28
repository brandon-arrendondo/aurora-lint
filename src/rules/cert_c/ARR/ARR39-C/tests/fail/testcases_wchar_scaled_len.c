/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR39-C violation
 * Settings: data_model=lp64, wchar_t_bits=32
 *
 * The wchar_t width is declared, so the array steps by 4 bytes and a
 * count scaled by sizeof(wchar_t) is scaled twice, inside a call's
 * argument as anywhere else.
 */

/*
 * Rule: ARR39-C - Do not add or subtract a scaled integer to a pointer
 * Status: FAIL
 * Reason: Multiplying string length by sizeof(wchar_t) causes double-scaling
 */

#include <wchar.h>
#include <stdio.h>

enum { WCHAR_BUF = 128 };

void func(void) {
    wchar_t error_msg[WCHAR_BUF];

    wcscpy(error_msg, L"Error: ");

    // Manually scaling by sizeof(wchar_t) - double-scaling
    fgetws(error_msg + wcslen(error_msg) * sizeof(wchar_t),  /* Expect: here */
           WCHAR_BUF - 7, stdin);
}

int main(void) {
    func();
    return 0;
}
