/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's compliant solution)
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * Every enumerator returns, and the fallback after the switch calls
 * `unreachable_color`, declared `_Noreturn` with no body in view. The
 * default and strict policies trust the keyword (C11 6.7.4p8), as CERT
 * MSC37-C-EX2 does, so control cannot reach the closing brace. The pedantic
 * policy accepts only a body verified never to return, so the function may
 * fall off its end.
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
