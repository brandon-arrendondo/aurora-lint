/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * A write of the pointer BEFORE its null test leaves the test in force:
 * in `p = other(), (p != 0 && *p)` the test reads the new value, and
 * nothing writes `p` again before `*p`. Moving the pointer by arithmetic
 * (`p++`) between the test and the dereference keeps it non-null, and a
 * call cannot write a local whose address is never taken. A second
 * assignment inside the test, `(p = a()) == NULL && (p = b()) == NULL`,
 * is tested by the same condition.
 */

#include <stddef.h>

char *get(void);
char *other(void);
void note_missing(void);
void touch(void);

int write_before_the_test(char *p)
{
    if (p == NULL)
        note_missing();
    return (p = other(), (p != 0 && *p));
}

int arithmetic_between(char *p)
{
    if (p == NULL)
        note_missing();
    return p && (p++, *p);
}

int call_between(char *p)
{
    if (p == NULL)
        note_missing();
    return p && (touch(), *p);
}

int assignment_then_arithmetic(void)
{
    char *p;
    return (p = get()) != NULL && (p += 1, *p);
}

int write_in_the_arm_not_taken(char *p)
{
    if (p == NULL)
        note_missing();
    return p == NULL ? (p = other()) != NULL : *p;
}

int second_lookup_tested_in_the_same_condition(void)
{
    char *p;
    if (((p = get()) == NULL && (p = other()) == NULL) || *p == 0)
        return 1;
    return 0;
}
