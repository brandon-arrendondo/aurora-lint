/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A store after the access reaches it on the next trip
 * Expect: count=1
 *
 * The first trip reads index 1, and every later one the 9 stored after
 * the access.
 */

int buf[4];

int total(int n)
{
    int i = 1;
    int r = 0;
    while (n > 0) {
        r += buf[i]; /* Expect: here */
        i = 9;
        n--;
    }
    return r;
}
