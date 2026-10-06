/*
 * Rule: CWE-327
 * Status: PASS - Use of strong AES cipher via OpenSSL
 */

typedef void EVP_CIPHER;
const EVP_CIPHER *EVP_aes_256_cbc(void);

void f(void) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  /* AES-256 is strong */
}
