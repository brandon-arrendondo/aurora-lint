/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - `K` is a `const` object, not a constant expression in C, so `x = K` copies a variable's value and is no default
 */

int get(void);

int f(void)
{
    const int K = 5;
    int x = K;
    x = get();
    return x + K;
}
