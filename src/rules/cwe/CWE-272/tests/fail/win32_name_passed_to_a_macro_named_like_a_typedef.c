/*
 * Rule: CWE-272
 * Status: FAIL - `trace (RegDeleteKeyA);` is a use of the function-like
 *         macro `trace`, which the preprocessor expands before the typedef
 *         of that name means anything, so it declares no pointer and the
 *         call after it is the Win32 API
 */

#include <windows.h>

typedef LONG (*trace)(HKEY, LPCSTR);
void log_fn(trace);
#define trace(x) log_fn(x)

void f(void)
{
    trace (RegDeleteKeyA);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: no pointer was declared */
}
