/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The statement expression's store always runs
 *
 * The masked store is a statement of a GNU statement expression that runs
 * whenever its statement does, so it replaces the out-of-range 99 before
 * the read.
 */

extern int get(void);

int masked(void)
{
    int buf[64] = {0};
    int n = 99;
    (void)({ n = get() & 63; 1; });
    return buf[n];
}
