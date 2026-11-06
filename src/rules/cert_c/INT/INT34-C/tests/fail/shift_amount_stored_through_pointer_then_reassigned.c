/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A comma expression stores through the pointer, then assigns the amount
 *
 * The comma expression's right operand sets `s` back to 40 after the
 * store through `q`.
 */

int mask(void)
{
    int s = 40;
    int *q = &s;
    (*q = 2, s = 40);
    return 1 << s;
}
