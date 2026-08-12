/*
 * Rule: MSC13-C
 * Status: PASS - Variable is read as the initializer value of another
 * declaration (not the declarator being initialized).
 */

int f(void) {
    int x = 42;
    int y = x;
    return y;
}
