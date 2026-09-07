/*
 * Rule: MSC12-C
 * Status: PASS - Should NOT trigger MSC12-C violation
 */

/*
 * Reason: an empty `default: break;` is MISRA C 2012 Rule 16.4 compliance --
 * every switch shall have a default label, and `break` is the canonical way
 * to say "every other value is deliberately ignored". Compilers ask for it
 * under -Wswitch-default. Removing it is a standards regression, not a
 * cleanup (task 999; the shape recurs across curl, lua and raylib).
 *
 * Distinct from testcases_empty_case_acting_default.c: here the default does
 * nothing, so the surrounding cases stay flagged on their own merits -- there
 * is deliberately no empty `case` in this file to confuse the two exemptions.
 */

extern void handle_one(void);
extern void handle_two(void);

void dispatch(int kind)
{
    switch (kind) {
    case 1:
        handle_one();
        break;
    case 2:
        handle_two();
        break;
    default:
        break;
    }
}
