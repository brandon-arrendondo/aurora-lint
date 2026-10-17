/*
 * Rule: CWE-272
 * Status: FAIL - a Win32 registry name is still the Win32 API where no
 *         pointer of that name is declared: a product inside a call of a
 *         call (`scale(FACTOR * RegDeleteKeyA)(0)`, with `FACTOR` a number
 *         behind a comment) declares nothing
 */

#include <windows.h>

#define FACTOR /* ms */ 2

typedef int (*scaler)(int);
scaler scale(long);

void f(void)
{
    scale(FACTOR * RegDeleteKeyA)(0);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: no pointer was declared */
}
