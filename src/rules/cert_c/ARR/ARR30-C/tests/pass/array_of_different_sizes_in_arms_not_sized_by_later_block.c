/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An array of different sizes in exclusive arms claims no bound
 *
 * Which arm is compiled depends on a macro this analysis does not evaluate,
 * so neither size is a fact, and the local of a later block is not what the
 * access names either.
 */

#ifdef SMALL
int buf[4];
#else
int buf[16];
#endif

int element(void)
{
    int r = buf[7];
    {
        int buf[2];
        buf[0] = 1;
        r += buf[0];
    }
    return r;
}
