/*
 * Rule: FLP03-C
 * Source: regression
 * Status: PASS - `a / b` in ratio divides two ints
 *
 * Another function declares its own `double a` and `double b`. A name is not
 * a variable: the operands here are ratio's own ints, so this is an integer
 * division (its zero divisor is INT33-C's concern, not this rule's).
 */

double average(void)
{
    double a = 1.0, b = 2.0;
    return (a + b) / 2.0;
}

int ratio(int a)
{
    int b = 0;
    return a / b;
}
