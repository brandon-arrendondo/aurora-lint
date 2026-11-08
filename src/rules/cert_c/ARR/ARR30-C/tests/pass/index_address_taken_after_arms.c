/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index is handed to a call by address
 *
 * The call may write it.
 */

void update(int *value);
int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
    update(&i);
    return buf[i];
}
