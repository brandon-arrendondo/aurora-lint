/*
 * Rule: CWE-272
 * Status: FAIL - RegOpenKeyExA opens an HKEY_LOCAL_MACHINE key with KEY_WRITE
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_WRITE 0x20006

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);

void f(void) {
    HKEY key;
    RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,  /* VIOLATION */
        "Software\\MyApp",
        0, KEY_WRITE, &key
    );
}
