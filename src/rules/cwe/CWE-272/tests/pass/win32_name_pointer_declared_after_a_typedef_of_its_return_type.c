/*
 * Rule: CWE-272
 * Status: PASS - with no macro of its name, `handler (*RegDeleteKeyA)(int);`
 *         declares a local pointer to a function returning a `handler`, and
 *         the call through it is not the Win32 API
 */

#include <windows.h>

typedef LONG (*handler)(HKEY, LPCSTR);

void f(handler (*lookup)(int))
{
    handler (*RegDeleteKeyA)(int);
    RegDeleteKeyA = lookup;
    RegDeleteKeyA(0);
}
