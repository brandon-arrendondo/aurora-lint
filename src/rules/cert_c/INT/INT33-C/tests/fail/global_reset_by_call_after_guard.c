/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A call between the guard and the division resets the
 * file-scope divisor
 */

int divisor;

void reset(void)
{
    divisor = 0;
}

int ratio(int a)
{
    if (divisor == 0)
        return 0;
    reset();
    return a / divisor;
}
