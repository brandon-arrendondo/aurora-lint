/*
 * Rule: MSC12-C
 * Status: PASS - a label must be followed by a statement, so `;` is the
 *         minimal legal way to say "this case does nothing" (sqlite's
 *         fossildelta.c and sqlite3rbu.c both write `default: ;`). Removing
 *         it does not compile. Same argument check_empty_switch_case already
 *         accepts for MISRA C 2012 Rule 16.4's `default: break;`.
 */

int classify(int op)
{
    switch (op) {
    case 1:
        return 10;
    default:  ;
    }
    return 0;
}
