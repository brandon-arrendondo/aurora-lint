/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An inner block's in-range value does not bound the outer index
 * Expect: count=1
 *
 * The outer `i` is read from outside through a pointer to it and never
 * checked. The inner block declares its own `i`, 2, which is in range for
 * `buf`; after the block `i` is the outer variable again, and nothing
 * bounds it.
 */

int read_untrusted(void);

int get(void)
{
    int buf[3];
    int i = 1;
    int *q = &i;
    *q = read_untrusted();
    {
        int i = 2;
        buf[i] = 1;
    }
    return buf[i]; /* Expect: here */
}
