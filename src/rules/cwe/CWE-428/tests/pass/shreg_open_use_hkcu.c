/*
 * Rule: CWE-428
 * Status: PASS - SHRegOpenUSKeyA with fIgnoreHKCU=FALSE
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef int BOOL;

#define FALSE 0

LONG SHRegOpenUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, BOOL);

void f(void) {
    HUSKEY key;
    SHRegOpenUSKeyA(
        "Software\\MyApp",
        0,
        0,
        &key,
        FALSE  /* Compliant: tries HKCU first */
    );
}
