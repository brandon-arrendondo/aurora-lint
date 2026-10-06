/*
 * Rule: CWE-428
 * Status: FAIL - CreateProcessW with unquoted path containing spaces
 */

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef const wchar_t *LPCWSTR;
typedef wchar_t *LPWSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef void *LPSTARTUPINFOW;
typedef void *LPPROCESS_INFORMATION;

BOOL CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, void*, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

void f(void) {
    CreateProcessW(
        0,
        L"C:\\Program Files\\MyApp\\app.exe -flag",  /* VIOLATION */
        0, 0, 0, 0, 0, 0, 0, 0
    );
}
