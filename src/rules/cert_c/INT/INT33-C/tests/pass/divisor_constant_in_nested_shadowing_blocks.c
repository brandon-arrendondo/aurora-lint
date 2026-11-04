/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Each division reads the variable its own block declares
 *
 * Three nested blocks each declare an `x`. Only the middle one holds a value
 * read from outside, and no division reads it.
 */

int read_untrusted(void);

int nested_ratio(void)
{
    int x = 1;
    {
        int x = read_untrusted();
        {
            int x = 4;
            (void)(100 / x);
        }
        (void)x;
    }
    return 100 / x;
}
