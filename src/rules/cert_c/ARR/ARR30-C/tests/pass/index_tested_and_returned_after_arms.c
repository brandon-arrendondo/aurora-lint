/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A later test returns on the value past the end
 *
 * Nothing past the end reaches the access.
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
        return 0;
    }
    return buf[i];
}
