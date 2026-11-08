/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The value past the end is overwritten in the #else of an empty #if 0
 *
 * The #else always runs.
 */

int buf[4];
int c;

int element(void)
{
    int i = 9;
#if 0
#else
    i = 1;
#endif
    return buf[i];
}
