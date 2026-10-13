/*
 * Rule: CWE-272
 * Status: PASS - SHRegOpenUSKeyA with fIgnoreHKCU=TRUE and KEY_READ only
 *         reads the HKLM key
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define TRUE 1
#define KEY_READ 0x20019

LONG SHRegOpenUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, BOOL);

void f(void) {
    HUSKEY key;
    SHRegOpenUSKeyA(
        "Software\\MyApp",
        KEY_READ,
        0,
        &key,
        TRUE  /* Compliant: HKLM, but read access */
    );
}
