/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - a block-scope prototype of `abs` still names the library's
 * Settings: data_model=lp64
 *
 * `int abs(int);` inside the function declares the library function, not
 * an object, so the guard bounds `data` to -181..181 and the square fits.
 */
void printIntLine(int);

void declared_here(short data)
{
    int abs(int);
    if (abs(data) <= 181)
    {
        short result = data * data;
        printIntLine(result);
    }
}
