/*
 * Rule: INT07-C
 * Source: aurora-lint (misfire: a local int read as the char it shadows)
 * Status: PASS - Should NOT trigger INT07-C violation
 *
 * Every arithmetic operand is an int that shares its name with a plain
 * char declared in an outer scope. The char itself is never used as a
 * number.
 */
char level;

int bump(void) {
    int level = 0;
    level++;
    level = level + 1;
    return level;
}

int scale(void) {
    char c = 'a';
    {
        int c = 3;
        c = c * 2;
        return c;
    }
}
