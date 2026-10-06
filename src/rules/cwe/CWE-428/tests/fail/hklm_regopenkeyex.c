/*
 * Rule: CWE-428
 * Status: FAIL - RegOpenKeyExA with HKEY_LOCAL_MACHINE
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);

void f(void) {
    HKEY key;
    RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,  /* VIOLATION */
        "Software\\MyApp",
        0, 0, &key
    );
}
