/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0x7fu is 127. Only the u is a suffix; the f before it is a
 *   hexadecimal digit, so the constant is not a value of 0 to 10.
 */

int is_delete(unsigned x) {
    if (x == 0x7fu) {
        return 1;
    }
    return 0;
}
