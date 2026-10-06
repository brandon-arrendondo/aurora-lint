/*
 * Rule: CWE-428
 * Status: FAIL - RegCreateKeyExW with HKEY_CLASSES_ROOT
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const wchar_t *LPCWSTR;
typedef wchar_t *LPWSTR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef HKEY *PHKEY;

#define HKEY_CLASSES_ROOT ((HKEY)(unsigned long)0x80000000)

LONG RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD,
    DWORD, LPSECURITY_ATTRIBUTES, PHKEY, DWORD*);

void f(void) {
    HKEY key;
    RegCreateKeyExW(
        HKEY_CLASSES_ROOT,  /* VIOLATION: HKCR also requires admin */
        L"Software\\MyApp",
        0, 0, 0, 0, 0, &key, 0
    );
}
