/*
 * Rule: CWE-327
 * Status: FAIL - Use of weak DES cipher via OpenSSL
 */

typedef void EVP_CIPHER;
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_cbc(void);

void f(void) {
    const EVP_CIPHER *cipher = EVP_des_cbc();  /* VIOLATION: DES is weak */
}
