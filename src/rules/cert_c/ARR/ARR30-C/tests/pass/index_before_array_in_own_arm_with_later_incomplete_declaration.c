/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The array in the access's own arm is declared after it
 *
 * The four-element declaration comes after the function, so it does not say
 * what the access indexes, though it is in the same arm. The other
 * declaration in the file gives no size.
 */

#ifdef WITH_BUF
int element(void)
{
    return buf[5];
}

char buf[4];
#endif

extern char buf[];
