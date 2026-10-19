/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0x3F is 63, not 0x3. In a hexadecimal constant f and F are
 *   digits, not a float suffix; reading them as one turned this literal
 *   into a value of 0 to 10 and exempted it.
 */

int below_limit(int c) {
    if (c >= 0x3F) {
        return 0;
    }
    return 1;
}
