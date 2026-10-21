/*
 * Rule: INT07-C
 * Source: aurora-lint
 * Status: FAIL - a plain char used as a number
 *
 * Inside the inner block `c` is an int. After the block it is the plain
 * char again, and incrementing it depends on whether char is signed.
 */
int scale(void) {
    char c = 'a';
    {
        int c = 3;
        c = c * 2;
    }
    c++;
    return c;
}
