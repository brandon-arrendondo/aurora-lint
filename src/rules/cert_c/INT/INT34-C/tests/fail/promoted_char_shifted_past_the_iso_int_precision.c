/*
 * Rule: INT34-C
 * Status: FAIL - an unsigned char promotes to a signed int, whose precision
 * is 31 or less
 *
 * No data model is declared. The default preset then assumes LP64, where the
 * promoted int has precision 31; the strict preset credits only ISO C's
 * guaranteed 16 bits, precision 15. A shift by 31 is out of range under both.
 */

int char_shifted_by_31(unsigned char c)
{
    return c << 31;
}
