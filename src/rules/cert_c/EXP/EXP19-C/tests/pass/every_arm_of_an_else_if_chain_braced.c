/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: An if, its else-if arms and its final else, each with
 * braces, give no unbraced body to report, whichever line an arm starts on
 * and whatever comment sits between an `else` and its brace.
 */

int classify(int value)
{
    int kind;

    if (value > 100) {
        kind = 3;
    } else if (value > 10) {
        kind = 2;
    }
    else /* small values */ {
        kind = 1;
    }

    if (value < 0) {
        kind = -kind;
    }
    else
    {
        kind = kind + 1;
    }

    return kind;
}
