/*
 * Rule: WIN30-C
 * Source: custom
 * Status: FAIL - Should trigger WIN30-C violation
 * Description: FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER, ...) allocates
 * with LocalAlloc and must be released with LocalFree; GlobalFree is the
 * wrong family. The wide entry point the FormatMessage macro expands to
 * under UNICODE was not matched (task 1130).
 */

#include <windows.h>

void report(DWORD err) {
    LPWSTR buf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    if (buf) {
        GlobalFree(buf);
    }
}
