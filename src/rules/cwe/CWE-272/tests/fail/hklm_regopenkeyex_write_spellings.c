/*
 * Rule: CWE-272
 * Status: FAIL - RegOpenKeyExA opens HKEY_LOCAL_MACHINE keys with a write
 *         right spelled as part of a compound mask, through an alias, or as
 *         a number
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_READ 0x20019
#define KEY_SET_VALUE 0x0002
#define KEY_CREATE_SUB_KEY 0x0004
#define APP_ACCESS KEY_SET_VALUE

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);

void f(void) {
    HKEY key;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: a write right among reads */
                  "SOFTWARE", 0, KEY_READ | KEY_CREATE_SUB_KEY, &key);
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: alias of KEY_SET_VALUE */
                  "SOFTWARE", 0, APP_ACCESS, &key);
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: KEY_WRITE's value */
                  "SOFTWARE", 0, 0x20006, &key);
}
