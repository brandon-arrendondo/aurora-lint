/*
 * Rule: CWE-272
 * Status: FAIL - SHRegOpenUSKeyA with fIgnoreHKCU=TRUE and KEY_WRITE opens
 *         the HKLM key for writing
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define TRUE 1
#define KEY_WRITE 0x20006

LONG SHRegOpenUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, BOOL);

void f(void) {
    HUSKEY key;
    SHRegOpenUSKeyA(
        "Software\\MyApp",
        KEY_WRITE,
        0,
        &key,
        TRUE  /* VIOLATION: fIgnoreHKCU=TRUE means HKLM only */
    );
}
