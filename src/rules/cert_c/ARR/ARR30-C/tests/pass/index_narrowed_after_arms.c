/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A later test clamps the index
 *
 * The test rewrites the value past the end.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    if (i >= 4) {
        i = 0;
    }
    return buf[i];
}
