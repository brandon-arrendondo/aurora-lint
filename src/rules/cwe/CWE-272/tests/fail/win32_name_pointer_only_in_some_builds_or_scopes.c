/*
 * Rule: CWE-272
 * Status: FAIL - a Win32 registry name is still the Win32 API where no
 *         function pointer of that name is in scope: a pointer declared only
 *         under `#ifdef` leaves the API wherever it is not compiled, a
 *         pointer local to another function is out of scope, and a
 *         prototype declares the API itself
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)

#ifdef USE_DYNAMIC_ADVAPI
LONG (*RegDeleteKeyA)(HKEY, LPCSTR);
#else
LONG RegDeleteKeyA(HKEY, LPCSTR);
#endif

LONG RegDeleteValueA(HKEY, LPCSTR);

void g(void)
{
    LONG (*RegDeleteValueA)(HKEY, LPCSTR) = 0;
    (void)RegDeleteValueA;
}

void f(void)
{
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");     /* VIOLATION: the API without USE_DYNAMIC_ADVAPI */
    RegDeleteValueA(HKEY_LOCAL_MACHINE, "v");                 /* VIOLATION: g's pointer is not in scope */
}
