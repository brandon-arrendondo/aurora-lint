/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A called function rewrites the file-scope index
 * Expect: count=1
 *
 * `refresh` assigns `gi` an unchecked value, and it runs between the
 * assignment of 2 and the access.
 */

int read_untrusted(void);

int gi;
int buf[4];

void refresh(void)
{
    gi = read_untrusted();
}

int element(void)
{
    gi = 2;
    refresh();
    return buf[gi]; /* Expect: here */
}
