/*
 * Rule: CWE-272
 * Status: FAIL - `trace (*RegDeleteKeyA)(0);` is a use of the function-like
 *         macro `trace`, which the preprocessor expands before the typedef
 *         of that name means anything, so it declares no pointer and the
 *         call after it is the Win32 API
 */

#include <windows.h>

typedef LONG (*trace)(HKEY, LPCSTR);
trace log_fn(void *);
#define trace(x) log_fn(x)

void f(void)
{
    trace (*RegDeleteKeyA)(0);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: no pointer was declared */
}
