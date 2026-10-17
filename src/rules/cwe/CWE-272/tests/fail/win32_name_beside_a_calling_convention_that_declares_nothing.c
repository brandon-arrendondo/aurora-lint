/*
 * Rule: CWE-272
 * Status: FAIL - a Win32 registry name is still the Win32 API where no
 *         pointer of that name is declared: a product inside a call of a
 *         call (`scale(FACTOR * RegDeleteKeyA)(0)`, with `FACTOR` a number)
 *         declares nothing, a pointer with a calling convention local to
 *         another function is out of scope, and a prototype with one
 *         declares the API itself
 */

#include <windows.h>

#define FACTOR 2

typedef int (*scaler)(int);
scaler scale(long);

LONG WINAPI RegDeleteValueA(HKEY, LPCSTR);

void g(void)
{
    LONG (WINAPI *RegDeleteValueA)(HKEY, LPCSTR) = 0;
    (void)RegDeleteValueA;
}

void f(void)
{
    scale(FACTOR * RegDeleteKeyA)(0);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: no pointer was declared */
    RegDeleteValueA(HKEY_LOCAL_MACHINE, "v");                 /* VIOLATION: g's pointer is not in scope */
}
