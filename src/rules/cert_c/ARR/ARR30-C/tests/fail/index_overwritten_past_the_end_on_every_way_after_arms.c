/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - Every way past the arms leaves the index past the end
 * Expect: count=1
 *
 * Both branches store 4, so whichever arm was built, the access reads
 * index 4. The value range at the access holds that one value.
 */

int buf[4];

int element(int c)
{
    int i = 1;
#if A
    i = 2;
#endif
    if (c)
        i = 4;
    else
        i = 4;
    return buf[i]; /* Expect: here */
}
