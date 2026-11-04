/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A block's extern of a name is the file-scope object, not the local it hides
 * Expect: count=1
 *
 * Inside the block, `extern int x` makes `x` the file-scope object again,
 * which is read from outside and never checked. The local `x` the block
 * hides is a nonzero constant, which says nothing of the object divided
 * by there. After the block the name is the local again, and dividing by
 * it is safe.
 */

int read_untrusted(void);

int x;

int ratio(void)
{
    int x = 1;
    {
        extern int x;
        x = read_untrusted();
        (void)(10 / x); /* Expect: here */
    }
    return 10 / x;
}
