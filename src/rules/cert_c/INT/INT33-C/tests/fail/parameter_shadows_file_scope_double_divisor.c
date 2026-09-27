/*
 * Rule: INT33-C
 * Source: regression
 * Status: FAIL - `10 / g` divides by the int parameter g without a zero check
 *
 * A file-scope `double g` shares the parameter's name. Inside `ratio` the
 * parameter hides it, so the divisor is an int. Resolving the occurrence
 * must reach the parameter before the file-scope declaration; typed by the
 * global, the division would read as floating-point and be skipped.
 */

double g;

int ratio(int g)
{
    return 10 / g;
}
