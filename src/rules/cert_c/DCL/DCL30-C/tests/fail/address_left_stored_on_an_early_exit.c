/*
 * Rule: DCL30-C
 * Status: FAIL - Should trigger DCL30-C violation
 * Reason: Each store of a local's address is undone on one path only: an
 *         early return, a goto and a break out of the loop holding the
 *         store each leave it in storage that outlives the call, and a
 *         reset that stores another local's address undoes nothing.
 */

struct db { int *p; };

int check(void);

int early_return(struct db *db)
{
    int n = 0;
    db->p = &n;                 /* VIOLATION */
    if (check())
        return -1;
    db->p = 0;
    return n;
}

int via_goto(struct db *db)
{
    int n = 0;
    db->p = &n;                 /* VIOLATION */
    if (check())
        goto out;
    db->p = 0;
out:
    return n;
}

void break_out_of_loop(struct db *db, int k)
{
    int n = 0;
    for (int i = 0; i < k; i++) {
        db->p = &n;             /* VIOLATION */
        if (check())
            break;
        db->p = 0;
    }
}

void reset_to_another_local(struct db *db)
{
    int a = 0, b = 0;
    db->p = &a;                 /* VIOLATION */
    db->p = &b;                 /* VIOLATION */
}
