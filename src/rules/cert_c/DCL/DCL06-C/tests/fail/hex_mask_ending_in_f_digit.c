/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0x7f is 127, not 0x7. In a hexadecimal constant f and F are
 *   digits, not a float suffix; reading them as one turned this literal
 *   into a value of 0 to 10 and exempted it.
 */

int low_seven_bits(int x) {
    return x & 0x7f;
}
