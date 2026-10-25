/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: Each arm of an if/else is its own body, and each unbraced
 * one is reported where that body starts. An unbraced if does not hide the
 * else after it, an if and its else on one line are two findings, and a
 * null body (`else ;`) is reported at its `;`.
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

    if (value == 7) kind = 7; else kind = 8;

    if (value == 9) {
        kind = 9;
    } else ;

    return kind;
}
