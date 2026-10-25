/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: Each arm of an if/else is its own body. When neither arm
 * has braces, both are reported: the if at the `if`, the else at the
 * `else`. An unbraced if does not hide the else after it, and an unbraced
 * else after a braced if is reported at the `else` line, not the `if`.
 */

int classify(int value)
{
    int kind;

    if (value < 0)
        kind = -1;
    else
        kind = 1;

    if (value == 0) {
        kind = 0;
    }
    else
        kind = kind * 2;

    if (value > 100)
        kind = 3;
    else if (value > 10)
        kind = 2;
    else
        kind = kind + 1;

    return kind;
}
