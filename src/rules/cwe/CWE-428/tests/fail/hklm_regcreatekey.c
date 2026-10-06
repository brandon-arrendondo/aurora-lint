/*
 * Rule: CWE-428
 * Status: FAIL - RegCreateKeyExA with HKEY_LOCAL_MACHINE
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)

LONG RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
    DWORD, LPSECURITY_ATTRIBUTES, PHKEY, DWORD*);

void f(void) {
    HKEY key;
    RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,  /* VIOLATION: uses HKLM, requires admin */
        "Software\\MyApp",
        0, 0, 0, 0, 0, &key, 0
    );
}
