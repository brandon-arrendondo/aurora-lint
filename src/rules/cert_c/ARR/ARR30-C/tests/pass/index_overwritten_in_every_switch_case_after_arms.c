/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every case of a later switch overwrites the index
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
    switch (c) {
    case 1:
        i = 0;
        break;
    default:
        i = 1;
        break;
    }
    return buf[i];
}
