/*
 * Rule: MSC13-C
 * Status: FAIL - resolving declarations under an unbraced `case` label
 * (task 756) must not blind the rule to a genuinely unused one. The `case`
 * arm declares `unused` and never reads it.
 */

void sink(int);

void f(int axis)
{
    switch (axis) {
        case 1:
            sink(axis);
            int unused = axis + 1;   /* VIOLATION: never read */
            break;
        default:
            break;
    }
}
