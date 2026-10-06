/*
 * Rule: CWE-428
 * Status: FAIL - CreateProcessA with unquoted path containing spaces
 */

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef void *LPSTARTUPINFOA;
typedef void *LPPROCESS_INFORMATION;

BOOL CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, void*, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);

void f(void) {
    CreateProcessA(
        0,
        "C:\\Program Files\\MyApp\\app.exe -flag",  /* VIOLATION: unquoted path with space */
        0, 0, 0, 0, 0, 0, 0, 0
    );
}
