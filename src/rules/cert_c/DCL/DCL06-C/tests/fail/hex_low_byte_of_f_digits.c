/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0x1f is 31, not 0x1. In a hexadecimal constant f and F are
 *   digits, not a float suffix; reading them as one turned this literal
 *   into a value of 0 to 10 and exempted it.
 */

int is_unit_separator(int x) {
    if (x == 0x1f) {
        return 1;
    }
    return 0;
}
