/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Both paths of a later if overwrite the index
 *
 * The value past the end is gone either way.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    if (c) {
        i = 0;
    } else {
        i = 1;
    }
    return buf[i];
}
