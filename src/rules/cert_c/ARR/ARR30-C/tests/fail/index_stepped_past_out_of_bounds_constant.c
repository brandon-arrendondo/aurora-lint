/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A stepped index past the end is reported at the index it holds
 *
 * `i = 4` is already out of bounds, and `i++` moves it to 5: the finding
 * names index 5, not the variable.
 */

int fill(void)
{
    int buf[4];
    int i = 4;
    i++;
    buf[i] = 1;
    return buf[0];
}
