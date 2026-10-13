/*
 * Rule: MSC13-C
 * Source: regression
 * Status: PASS - a store a continue carries out of a do loop is read after it
 *
 * A `continue` in a `do` body jumps to the condition, so when `k` is zero
 * the loop ends there and `n = 0` is the value returned. Only the
 * fallthrough path overwrites it.
 */

int count(int c, int k, int m) {
    int n;
    do {
        n = 0;
        if (c) {
            continue;
        }
        n = m;
    } while (k);
    return n;
}
