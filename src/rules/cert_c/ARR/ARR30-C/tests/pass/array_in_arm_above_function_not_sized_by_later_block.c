/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A file-scope array in an arm above the function is the one indexed
 *
 * The conditional holding the array closes before the function, so the
 * arm does not hold the access, and the local in the later block still
 * is not what the access names.
 */

#ifdef WITH_BUF
int buf[8];
#endif

int element(void)
{
    int r = buf[7];
    {
        int buf[4];
        buf[0] = 1;
        r += buf[0];
    }
    return r;
}
