/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The pointer's address is taken through parentheses
 *
 * `&(q)` lets `*pp` change `q`, so `*q = 2` need not write `s`.
 */

int mask(void)
{
    int s = 40;
    int *q = &s;
    int **pp = &(q);
    *pp = 0;
    *q = 2;
    return 1 << s;
}
