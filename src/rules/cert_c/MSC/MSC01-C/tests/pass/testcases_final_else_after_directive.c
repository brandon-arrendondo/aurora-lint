/*
 * Rule: MSC01-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MSC01-C violation
 */

/*
 * Rule: MSC01-C - Strive for logical completeness
 * Status: PASS
 * Reason: The chain ends in a final else, but tree-sitter-c cannot attach
 *         it: an `else` cannot begin a block item, so one following a
 *         directive is left outside the if_statement. The rule reads past
 *         comments and directive lines for it.
 *
 *         Distilled from curl lib/curlx/timeval.c: the final else sits in
 *         both arms of an #ifdef/#else, below a comment.
 */

int clock_now(int a, int b);

int now(int a, int b)
{
    int r = 0;
#ifdef HAVE_RAW
    if (clock_now(a, 1) == 0) {
        r = 1;
    }
    else
#endif

    if (clock_now(a, 2) == 0) {
        r = 2;
    }
    /*
     * fall back to another time source
     */
#ifdef HAVE_GETTIMEOFDAY
    else {
        r = 3;
    }
#else
    else {
        r = 4;
    }
#endif
    return r;
}
