/*
 * Rule: EXP34-C
 * Source: synthetic (pure-ftpd's `(s = getvalue(...)) == NULL || *s == 0`)
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The value of `(s = e)` is the new `s`, so a null test on it tests `s`:
 * the right operand of `(s = e) == NULL || *s` runs only when `s` is
 * non-null, as it does for `s = e; s == NULL || *s`. The same holds for
 * `!(s = e) || ...`, `(s = e) != NULL && ...`, `(s = e) && ...` and a
 * conditional's taken arm.
 */

#include <stdlib.h>
#include <string.h>

char *get(int);

int eq_null_or(void)
{
    char *s;
    if ((s = get(1)) == NULL || *s == 0)
        return 1;
    return 0;
}

int not_or(void)
{
    char *s;
    if (!(s = get(1)) || *s == 0)
        return 1;
    return 0;
}

int malloc_eq_null_or(void)
{
    char *s;
    if ((s = malloc(4)) == NULL || *s == 0)
        return 1;
    free(s);
    return 0;
}

int ne_null_and(void)
{
    char *s;
    if ((s = get(1)) != NULL && *s == 0)
        return 1;
    return 0;
}

int ne_null_and_library_call(void)
{
    const char *s;
    if ((s = get(1)) != NULL && strcmp(s, "x") == 0)
        return 1;
    return 0;
}

int conditional(void)
{
    char *s;
    return (s = get(1)) ? *s : 0;
}
