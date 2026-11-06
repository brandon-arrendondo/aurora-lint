/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A call may rewrite the object a block extern declaration names
 * Expect: count=1
 *
 * The block's `extern int gi` names a file-scope object, which
 * `refresh` may assign.
 */

int buf[4];

void refresh(void);

int element(void)
{
    extern int gi;
    gi = 2;
    refresh();
    return buf[gi]; /* Expect: here */
}
