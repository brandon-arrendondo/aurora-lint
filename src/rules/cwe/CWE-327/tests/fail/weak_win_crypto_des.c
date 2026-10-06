/*
 * Rule: CWE-327
 * Status: FAIL - Windows CryptDeriveKey with CALG_DES
 */

typedef unsigned long HCRYPTPROV;
typedef unsigned long HCRYPTHASH;
typedef unsigned long *HCRYPTKEY;
typedef unsigned long ALG_ID;
typedef int BOOL;

#define CALG_DES 0x00006601

BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hHash,
                    unsigned long dwFlags, HCRYPTKEY *phKey);

void f(HCRYPTPROV prov, HCRYPTHASH hash) {
    HCRYPTKEY key;
    CryptDeriveKey(prov, CALG_DES, hash, 0, &key);  /* VIOLATION: weak DES */
}
