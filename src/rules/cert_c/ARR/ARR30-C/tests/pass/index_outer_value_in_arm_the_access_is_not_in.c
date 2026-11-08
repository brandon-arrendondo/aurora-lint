/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The access keeps the block's index
 *
 * The inner block's arm holds both the declaration and the access, so the
 * outer 9 is never used there.
 */

int buf[4];

int element(void)
{
    int i = 9;
    {
#if defined(A)
        int i = 1;
        return buf[i];
#endif
    }
    return i;
}
