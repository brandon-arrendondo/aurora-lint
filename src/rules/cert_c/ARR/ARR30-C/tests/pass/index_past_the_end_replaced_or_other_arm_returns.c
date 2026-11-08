/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm without a store returns
 *
 * The value past the end reaches the access in no configuration.
 */

int buf[4];
int c;

int element(void)
{
    int i = 9;
#if A
    i = 1;
#else
    return 0;
#endif
    return buf[i];
}
