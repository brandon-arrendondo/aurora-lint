/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation. CERT's "Compliant
 * Solution" label here is about a DIFFERENT structural point (removing
 * an early return makes the trailing "if (s)" reachable, per the live
 * wiki) -- it isn't claiming the empty comment-only if-bodies
 * themselves are meaningful code. Both empty-body if statements below
 * are mechanically empty with no effect, which is exactly what
 * MSC12-C targets; aurora-lint's detection is correct even though the wiki
 * used placeholder comments instead of real code for illustration.
 */

int func(int condition) {
    char *s = NULL;
    if (condition) {
        s = (char *)malloc(10);
        if (s == NULL) {
           /* Handle error */
        }
        /* Process s */
    }
    /* Code that doesn't touch s */
    if (s) {
        /* This code is now reachable */
    }
    return 0;
}