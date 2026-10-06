/*
 * Rule: CWE-327
 * Status: FAIL - Use of weak RC4 cipher via OpenSSL
 */

typedef void EVP_CIPHER;
const EVP_CIPHER *EVP_rc4(void);

void f(void) {
    const EVP_CIPHER *cipher = EVP_rc4();  /* VIOLATION: RC4 is weak */
}
