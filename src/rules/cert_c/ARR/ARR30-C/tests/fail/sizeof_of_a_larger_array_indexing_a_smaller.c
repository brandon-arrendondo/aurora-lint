/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - `sizeof(big) - 1` is past the end of the smaller array
 * Expect: count=1
 *
 * The operand of `sizeof` is the sixteen-element array, resolved at the
 * operand, and indexes the four-element one.
 */

int element(void)
{
    char big[16];
    char small[4];
    big[0] = 1;
    return small[sizeof(big) - 1];
}
