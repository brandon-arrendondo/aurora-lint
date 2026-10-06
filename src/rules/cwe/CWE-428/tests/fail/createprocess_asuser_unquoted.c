/*
 * Rule: CWE-428
 * Status: FAIL - CreateProcessAsUserA with unquoted path (arg index 2)
 */

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef void *LPSTARTUPINFOA;
typedef void *LPPROCESS_INFORMATION;

BOOL CreateProcessAsUserA(HANDLE, LPCSTR, LPSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
    DWORD, void*, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

void f(void) {
    CreateProcessAsUserA(
        0,
        0,
        "C:\\Program Files\\MyApp\\app.exe",  /* VIOLATION: arg index 2 */
        0, 0, 0, 0, 0, 0, 0, 0
    );
}
