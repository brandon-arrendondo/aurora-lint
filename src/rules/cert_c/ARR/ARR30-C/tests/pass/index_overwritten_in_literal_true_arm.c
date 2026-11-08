/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The value past the end is overwritten under #if 1
 *
 * Nothing passes around the arm.
 */

int buf[4];
int c;

int element(void)
{
    int i = 9;
#if 1
    i = 1;
#endif
    return buf[i];
}
