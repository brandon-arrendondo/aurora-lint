/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A store before `continue` reaches the access on the next pass
 * Expect: count=1
 *
 * On the pass where `k` is 2, `i` becomes 9 and `continue` goes round the
 * loop, so every later pass reads `buf[9]` of `buf[5]`.
 */

int sum(int n)
{
    int buf[5] = {0};
    int r = 0;
    int i = 1;
    for (int k = 0; k < n; k++) {
        r += buf[i]; /* Expect: here */
        if (k == 2) {
            i = 9;
            continue;
        }
    }
    return r;
}
