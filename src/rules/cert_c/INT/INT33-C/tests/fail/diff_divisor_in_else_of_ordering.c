/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The division is in the branch where hi <= lo
 *
 * `hi > lo` proves hi - lo non-zero in its true branch only. In the else
 * branch hi may equal lo.
 */

int scale(int v, int hi, int lo)
{
    if (hi > lo) {
        return v;
    } else {
        return v / (hi - lo);
    }
}
