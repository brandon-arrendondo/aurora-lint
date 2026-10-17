/*
 * Rule: CWE-272
 * Status: FAIL - a Win32 registry name is still the Win32 API when the
 *         statement before it only looks like a declaration with a
 *         parenthesized declarator: `trace (RegDeleteKeyA);` with `trace` a
 *         function, not a typedef, passes the API's address on and declares
 *         nothing
 */

typedef void *HKEY;
typedef long LONG;
typedef const char *LPCSTR;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)

LONG RegDeleteKeyA(HKEY, LPCSTR);
void trace(LONG (*fn)(HKEY, LPCSTR));

void f(void)
{
    trace (RegDeleteKeyA);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");      /* VIOLATION: the API */
}
