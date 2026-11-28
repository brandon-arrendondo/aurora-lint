/*
 * Rule: ARR39-C
 * Source: wiki
 * Status: FAIL - Should trigger ARR39-C violation
 * Settings: data_model=lp64, wchar_t_bits=32
 *
 * A wchar_t is as wide as the platform makes it; declared 4 bytes here, so
 * the array steps by 4 and the count scaled by sizeof(wchar_t) scales twice.
 */

#include <wchar.h>
#include <stdio.h>
 
enum { WCHAR_BUF = 128 };
 
void func(void) {
  wchar_t error_msg[WCHAR_BUF];

  wcscpy(error_msg, L"Error: ");
  fgetws(error_msg + wcslen(error_msg) * sizeof(wchar_t), 
         WCHAR_BUF - 7, stdin);
  /* ... */
}