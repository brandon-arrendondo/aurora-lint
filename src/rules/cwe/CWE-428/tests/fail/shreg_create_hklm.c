/*
 * Rule: CWE-428
 * Status: FAIL - SHRegCreateUSKeyA with SHREGSET_HKLM flag
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define SHREGSET_HKLM 0x00000002

LONG SHRegCreateUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, DWORD);

void f(void) {
    HUSKEY key;
    SHRegCreateUSKeyA(
        "Software\\MyApp",
        0,
        0,
        &key,
        SHREGSET_HKLM  /* VIOLATION: targets HKLM */
    );
}
