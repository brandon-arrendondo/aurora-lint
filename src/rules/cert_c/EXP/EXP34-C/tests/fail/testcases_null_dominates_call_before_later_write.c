/*
 * Rule: EXP34-C
 * Status: FAIL - `p` is NULL when `sink` is called; the non-null write comes
 *         after the call. A whole-function "last write wins" table read the
 *         later `&local` and passed the call as non-null; the assignment that
 *         dominates the call says NULL.
 */

static int sink(const int *ptr)
{
    return *ptr;
}

int caller(void)
{
    int local = 3;
    const int *p = &local;
    int r;

    p = NULL;
    r = sink(p);
    p = &local;
    return r + *p;
}
