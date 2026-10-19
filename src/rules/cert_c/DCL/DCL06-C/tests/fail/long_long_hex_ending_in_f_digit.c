/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0x1fLL is 31. Only LL is a suffix; the f before it is a
 *   hexadecimal digit, so the constant is not a value of 0 to 10.
 */

int is_low_field(long long x) {
    if (x > 0x1fLL) {
        return 1;
    }
    return 0;
}
