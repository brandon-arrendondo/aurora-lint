/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A later if overwrites the index or returns
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
        return 0;
    }
    return buf[i];
}
