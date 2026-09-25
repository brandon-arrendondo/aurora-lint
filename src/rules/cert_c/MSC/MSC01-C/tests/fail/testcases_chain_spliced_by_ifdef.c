/*
 * Rule: MSC01-C
 * Source: testcases
 * Status: FAIL - Should trigger MSC01-C violation
 */

/*
 * Rule: MSC01-C - Strive for logical completeness
 * Status: FAIL
 * Reason: An else-if chain continued across #ifdef blocks is still one
 *         chain, and this one has no final else in any configuration. The
 *         `else if` after a directive is not a final else: the rule follows
 *         the chain to its real tail and reports it there.
 *
 *         Distilled from hostap src/ap/wpa_auth_ie.c, the RSN key-management
 *         selector chain.
 */

int select_suite(int mgmt)
{
    int selector = 0;
    if (mgmt & 1)
        selector = 10;
    else if (mgmt & 2)
        selector = 20;
#ifdef CONFIG_FILS
    else if (mgmt & 4)
        selector = 40;
#endif
    else if (mgmt & 8)
        selector = 80;
    return selector;
}
