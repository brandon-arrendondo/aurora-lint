/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A byte up to 255 does not fit a plain char the project declares signed
 * Settings: data_model=lp64, char_signed=true
 * Expect: count=2
 *
 * The project declares plain `char` signed, so it holds at most 127. A
 * byte masked to `0xFF` can be up to 255, and so can the constant.
 */

void sink(int);

void stores(unsigned long n)
{
    char byte = (char)(n & 0xFF); /* Expect: here */
    char high = 200;              /* Expect: here */
    sink(byte + high);
}
