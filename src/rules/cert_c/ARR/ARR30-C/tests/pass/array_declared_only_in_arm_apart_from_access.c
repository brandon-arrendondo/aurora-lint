/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The array of 4 sits in an arm the access is never compiled with
 *
 * A repeated condition splits them, so the file shows no size for this access.
 */

#ifdef A
int buf[4];
#endif

int element(void)
{
#ifdef A
    return 0;
#else
    return buf[9];
#endif
}
