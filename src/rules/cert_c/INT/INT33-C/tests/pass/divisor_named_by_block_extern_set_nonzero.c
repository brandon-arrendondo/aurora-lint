/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - A block's extern of a name divides by the file-scope object's own value
 *
 * The local `x` is read from outside and never checked, but it is not what
 * either block uses. In each block `extern int x` names the file-scope
 * object instead: the first block gives it a nonzero value, and the second
 * divides by it.
 */

int read_untrusted(void);

int x;

int ratio(void)
{
    int x = read_untrusted();
    {
        extern int x;
        x = 5;
        x = x + 1;
    }
    {
        extern int x;
        (void)(10 / x);
    }
    return 0;
}
