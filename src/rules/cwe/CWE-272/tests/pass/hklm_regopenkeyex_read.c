/*
 * Rule: CWE-272
 * Status: PASS - RegOpenKeyExA opens HKEY_LOCAL_MACHINE keys for reading:
 *         a read there needs no administrator rights
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_READ 0x20019
#define KEY_QUERY_VALUE 0x0001
#define READ_ACCESS KEY_READ

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);

void f(void) {
    HKEY key;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, KEY_READ, &key);  /* Compliant: read */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, KEY_QUERY_VALUE, &key);  /* Compliant: read */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, 0x20019, &key);  /* Compliant: KEY_READ's value */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, READ_ACCESS, &key);  /* Compliant: alias of KEY_READ */
}
