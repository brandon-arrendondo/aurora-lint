/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - GET_VALUE() expands to a call, so its value is computed, not a default
 */

int get_value(void);

#define GET_VALUE() get_value()

int f(int c)
{
    int r = GET_VALUE();
    r = c;
    return r;
}
