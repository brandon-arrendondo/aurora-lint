/*
 * Rule: CWE-327
 * Status: PASS - Windows CryptDeriveKey with CALG_AES_256
 */

typedef unsigned long HCRYPTPROV;
typedef unsigned long HCRYPTHASH;
typedef unsigned long *HCRYPTKEY;
typedef unsigned long ALG_ID;
typedef int BOOL;

#define CALG_AES_256 0x00006610

BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hHash,
                    unsigned long dwFlags, HCRYPTKEY *phKey);

void f(HCRYPTPROV prov, HCRYPTHASH hash) {
    HCRYPTKEY key;
    CryptDeriveKey(prov, CALG_AES_256, hash, 0, &key);  /* AES-256: strong */
}
