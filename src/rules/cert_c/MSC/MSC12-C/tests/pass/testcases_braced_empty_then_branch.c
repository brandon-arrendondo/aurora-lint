/*
 * Rule: MSC12-C
 * Status: PASS - the braced form of the empty-then-branch idiom. The `;`
 *         absorbs its condition so the `else` arm does not run for it, and
 *         removing it changes which branch executes -- the same argument
 *         pass/testcases_empty_then_branch_with_else.c already rests on for
 *         the unbraced form (curl's hostip4.c writes the braced one).
 */

int lookup(int *h, int fallback)
{
    if (h) {
        ;
    }
    else {
        return fallback;
    }
    return *h;
}
