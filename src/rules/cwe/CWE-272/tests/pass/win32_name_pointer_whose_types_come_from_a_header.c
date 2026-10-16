/*
 * Rule: CWE-272
 * Status: PASS - a file-scope function pointer of a Win32 registry name
 *         whose return and parameter types come from a header this file
 *         does not show: nothing in the file says `LONG` is a type, but an
 *         expression statement cannot stand at file scope, so
 *         `LONG (*RegDeleteKeyA)(HKEY, LPCSTR);` declares the pointer
 */

#include <windows.h>

LONG (*RegDeleteKeyA)(HKEY, LPCSTR);

void f(void)
{
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* Compliant: a pointer */
}
