/*
 * Rule: CWE-327
 * Status: FAIL - Direct use of DES_ecb_encrypt
 */

typedef unsigned char DES_cblock[8];
typedef void DES_key_schedule;

void DES_ecb_encrypt(const DES_cblock *input, DES_cblock *output,
                     DES_key_schedule *ks, int enc);

void f(void) {
    DES_cblock in, out;
    DES_key_schedule ks;
    DES_ecb_encrypt(&in, &out, &ks, 1);  /* VIOLATION: direct DES use */
}
