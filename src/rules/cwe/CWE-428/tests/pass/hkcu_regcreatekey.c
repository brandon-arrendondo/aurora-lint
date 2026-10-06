/*
 * Rule: CWE-428
 * Status: PASS - RegCreateKeyExA with HKEY_CURRENT_USER (least privilege)
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef char *LPSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef HKEY *PHKEY;

#define HKEY_CURRENT_USER ((HKEY)(unsigned long)0x80000001)

LONG RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
    DWORD, LPSECURITY_ATTRIBUTES, PHKEY, DWORD*);

void f(void) {
    HKEY key;
    RegCreateKeyExA(
        HKEY_CURRENT_USER,  /* Compliant: HKCU */
        "Software\\MyApp",
        0, 0, 0, 0, 0, &key, 0
    );
}
