/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: FAIL - Should trigger DCL06-C violation
 * Description: 0xff is 255. When f was read as a suffix, stripping it left
 *   no digits at all, so this literal was reported anyway; keeping the
 *   digits must still report it. (As a mask, `x & 0xff` is the byte-mask
 *   idiom and exempt.)
 */

int is_all_ones_byte(unsigned x) {
    if (x == 0xff) {
        return 1;
    }
    return 0;
}
