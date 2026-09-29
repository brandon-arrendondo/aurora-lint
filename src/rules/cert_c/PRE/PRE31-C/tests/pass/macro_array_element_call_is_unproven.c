/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: TAB(1) expands to handlers[1](0), a call through an array element:
 * no body is named, so it is unproven and only the strict preset reports it.
 */

#define TAB(i) handlers[i](0)
#define TWICE(x) ((x) + (x))

int (*handlers[4])(int);

int u2(void) {
    return TWICE(TAB(1));
}
