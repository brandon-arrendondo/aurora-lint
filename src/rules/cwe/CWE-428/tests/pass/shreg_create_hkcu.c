/*
 * Rule: CWE-428
 * Status: PASS - SHRegCreateUSKeyA with SHREGSET_HKCU flag
 */

typedef void *HUSKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;

#define SHREGSET_HKCU 0x00000001

LONG SHRegCreateUSKeyA(LPCSTR, DWORD, HUSKEY, HUSKEY*, DWORD);

void f(void) {
    HUSKEY key;
    SHRegCreateUSKeyA(
        "Software\\MyApp",
        0,
        0,
        &key,
        SHREGSET_HKCU  /* Compliant: HKCU */
    );
}
