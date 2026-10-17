/*
 * Rule: CWE-272
 * Status: PASS - a Win32 registry name declared as a function pointer with a
 *         calling convention inside the declarator is that pointer, not the
 *         Win32 API: tree-sitter reads `LONG (WINAPI *f)(...)` as a call of
 *         `LONG` with `WINAPI * f`, and a calling convention is never a
 *         factor. At file scope or in a block, initialized or not, through
 *         the platform's macro, the keyword, or a macro this file defines
 */

#include <windows.h>

#define ADVAPI_CALL WINAPI

LONG (WINAPI *RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM,
                               LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);

void f(void)
{
    HKEY key;
    LONG (APIENTRY *RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    LONG (CALLBACK *RegDeleteKeyA)(HKEY, LPCSTR) = 0;
    LONG (__stdcall *RegDeleteValueA)(HKEY, LPCSTR);
    LONG (ADVAPI_CALL *RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
    DWORD one = 1;

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, 0, 0, KEY_WRITE, 0, &key, 0); /* Compliant: a pointer */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, KEY_WRITE, &key); /* Compliant: a pointer */
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");      /* Compliant: a pointer */
    RegDeleteValueA(HKEY_LOCAL_MACHINE, "Setting");            /* Compliant: a pointer */
    RegSetValueExA(HKEY_LOCAL_MACHINE, "Setting", 0, REG_DWORD, (const BYTE *)&one, sizeof one); /* Compliant: a pointer */
}
