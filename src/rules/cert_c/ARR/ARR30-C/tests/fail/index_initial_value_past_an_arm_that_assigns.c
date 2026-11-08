/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A build without the macro keeps the initial value
 * Expect: count=1
 *
 * Only the #if arm assigns the index, so without A it still holds 9.
 */

int buf[4];

int element(void)
{
    int i = 9;
#if defined(A)
    i = 1;
#endif
    return buf[i];
}
