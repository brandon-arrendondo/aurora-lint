/*
 * Rule: CWE-428
 * Status: FAIL - SHRegOpenUSKeyA with fIgnoreHKCU=TRUE
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define TRUE 1

LONG SHRegOpenUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, BOOL);

void f(void) {
    HUSKEY key;
    SHRegOpenUSKeyA(
        "Software\\MyApp",
        0,
        0,
        &key,
        TRUE  /* VIOLATION: fIgnoreHKCU=TRUE means HKLM only */
    );
}
