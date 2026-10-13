/*
 * Rule: CWE-272
 * Status: FAIL - RegSetValueExA, RegDeleteValueW and the <windows.h> macro
 *         spelling RegDeleteTree on HKEY_LOCAL_MACHINE write there, whatever
 *         access any earlier open asked for
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef const unsigned short *LPCWSTR;
typedef const unsigned char *LPCBYTE;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define REG_DWORD 4

LONG RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, LPCBYTE, DWORD);
LONG RegDeleteValueW(HKEY, LPCWSTR);
LONG RegDeleteTree(HKEY, LPCSTR);

void f(void) {
    DWORD one = 1;
    RegSetValueExA(HKEY_LOCAL_MACHINE,  /* VIOLATION */
                   "Setting", 0, REG_DWORD, (LPCBYTE)&one, sizeof one);
    RegDeleteValueW(HKEY_LOCAL_MACHINE,  /* VIOLATION */
                    0);
    RegDeleteTree(HKEY_LOCAL_MACHINE,  /* VIOLATION */
                  "Software\\MyApp");
}
