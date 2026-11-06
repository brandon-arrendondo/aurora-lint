/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A callee handed the pointer's address may repoint it
 *
 * `get` receives `&q` and may store another address in it, so `*q = 2`
 * may not write `s`.
 */

void get(int **pp);

int mask(void)
{
    int s = 40;
    int *q = &s;
    get(&q);
    *q = 2;
    return 1 << s;
}
