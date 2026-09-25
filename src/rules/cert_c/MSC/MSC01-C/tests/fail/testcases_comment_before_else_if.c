/*
 * Rule: MSC01-C
 * Source: testcases
 * Status: FAIL - Should trigger MSC01-C violation
 */

/*
 * Rule: MSC01-C - Strive for logical completeness
 * Status: FAIL
 * Reason: A comment between `else` and the next `if` does not end the chain.
 *         The chain below has no final else; reading the comment as the
 *         else's body stopped the walk one link early and missed that.
 */

int pick(int a)
{
    int r = 0;
    if (a == 1) {
        r = 1;
    } else /* second choice */ if (a == 2) {
        r = 2;
    }
    return r;
}
