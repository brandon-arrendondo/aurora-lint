/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's compliant solution)
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * Every enumerator returns, and the fallback after the switch calls
 * `unreachable_color`, declared `_Noreturn` with no body in view. The
 * default policy trusts the keyword (C11 6.7.4p8), so control cannot reach
 * the closing brace. The strict policy accepts only a body verified never
 * to return, so the function may fall off its end.
 */

enum color { RED, GREEN, BLUE };

_Noreturn void unreachable_color(enum color c);

int color_code(enum color c)
{
    switch (c) {
    case RED:
        return 1;
    case GREEN:
        return 2;
    case BLUE:
        return 3;
    }
    unreachable_color(c);
}
