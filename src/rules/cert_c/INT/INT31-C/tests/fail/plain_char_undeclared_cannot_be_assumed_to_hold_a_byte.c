/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A byte up to 255 may not fit a plain char nobody declares unsigned
 * Expect: count=2
 *
 * Whether plain `char` is signed is the implementation's choice, and this
 * project does not declare it. A byte masked to `0xFF` and the constant
 * 200 each fit an unsigned `char` but not a signed one, so neither is
 * proved to keep its value.
 */

void sink(int);

void stores(unsigned long n)
{
    char byte = (char)(n & 0xFF); /* Expect: here */
    char high = 200;              /* Expect: here */
    sink(byte + high);
}
