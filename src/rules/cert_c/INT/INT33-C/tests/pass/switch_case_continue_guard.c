/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The continue skips the division when d is zero
 *
 * Inside a case, the statements run in order, so the division after
 * `if (d == 0) continue;` runs only when d is non-zero.
 */

int sum(int a, const int *ds, int n, int k)
{
    int r = 0;
    for (int i = 0; i < n; i++) {
        int d = ds[i];
        switch (k) {
        case 0:
            if (d == 0)
                continue;
            r += a / d;
            break;
        default:
            break;
        }
    }
    return r;
}
