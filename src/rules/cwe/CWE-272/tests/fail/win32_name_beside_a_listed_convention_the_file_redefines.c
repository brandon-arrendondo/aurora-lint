/*
 * Rule: CWE-272
 * Status: FAIL - a name the platform headers spell a calling convention
 *         with is what this file defines it as: with `CALLBACK` a number,
 *         `scale(CALLBACK * RegDeleteKeyA)(0)` is a product, and declares
 *         no pointer
 */

#include <windows.h>

#undef CALLBACK
#define CALLBACK 2

typedef int (*scaler)(int);
scaler scale(long);

void f(void)
{
    scale(CALLBACK * RegDeleteKeyA)(0);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: no pointer was declared */
}
