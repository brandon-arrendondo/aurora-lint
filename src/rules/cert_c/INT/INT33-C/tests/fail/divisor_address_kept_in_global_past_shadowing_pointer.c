/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The divisor's address is kept in a file-scope pointer
 *
 * `g = &x` stores the address in the file-scope `g`: the block's own `g`
 * is declared after it and is another object. `run` may then write `x`
 * through the file-scope pointer, so nothing bounds `x` at the division.
 */

int *g;
void run(void);

int ratio(void)
{
    int x = 1;
    g = &x;
    {
        int *g = 0;
        (void)g;
    }
    run();
    return 100 / x;
}
