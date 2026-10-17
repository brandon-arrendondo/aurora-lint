/*
 * Rule: CWE-272
 * Status: FAIL - a pointer with a calling convention local to another
 *         function is out of scope, and a prototype with one declares the
 *         API itself
 */

#include <windows.h>

LONG WINAPI RegDeleteValueA(HKEY, LPCSTR);

void g(void)
{
    LONG (WINAPI *RegDeleteValueA)(HKEY, LPCSTR) = 0;
    (void)RegDeleteValueA;
}

void f(void)
{
    RegDeleteValueA(HKEY_LOCAL_MACHINE, "v");                 /* VIOLATION: g's pointer is not in scope */
}
