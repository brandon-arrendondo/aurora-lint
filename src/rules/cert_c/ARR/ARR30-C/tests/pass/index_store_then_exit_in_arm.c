/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm storing past the end exits
 *
 * The store never reaches the access.
 */

void exit(int status);
int buf[4];
int c;

int element(void)
{
    int i;
#if A
    i = 9;
    exit(i);
#else
    i = 1;
#endif
    return buf[i];
}
