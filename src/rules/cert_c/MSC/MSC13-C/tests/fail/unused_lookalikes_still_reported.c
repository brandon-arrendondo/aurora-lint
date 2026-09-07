/*
 * Rule: MSC13-C
 * Status: FAIL - Should trigger MSC13-C violations
 *
 * Guards the unused-attribute suppression (task 964) against the two ways it
 * could swallow real findings:
 *
 *   - a variable that is merely *named* `unused`. The bare token only counts
 *     inside `__attribute__(...)` or `[[...]]`, so this one is still
 *     reported.
 *   - a macro whose replacement text merely *contains* the substring
 *     "unused". `warn_unused_result` is one token and is not the `unused`
 *     attribute, so `CHECK_RESULT` does not annotate anything as
 *     legitimately-unused.
 */

#define CHECK_RESULT __attribute__((warn_unused_result))

extern int compute(void) CHECK_RESULT;

void f(void) {
    int unused = 42;
}

void g(void) {
    int result = compute();
}
