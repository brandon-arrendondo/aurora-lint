/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: -0x007f is -127, not -0x007. In a hexadecimal constant f and
 *   F are digits, not a float suffix; reading them as one turned this
 *   literal into a value of 0 to 10 and exempted it.
 */

int negative_bound(int x) {
    if (x < -0x007f) {
        return 1;
    }
    return 0;
}
