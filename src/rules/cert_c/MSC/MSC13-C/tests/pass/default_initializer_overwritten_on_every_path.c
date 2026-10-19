/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * MSC13-EX1: initializing a variable with a default value that every path
 * then overwrites may be inefficient, but is less of a problem than
 * reading an uninitialized value (EXP33-C). The default is any constant
 * expression on the declaration: 0, -1, NULL, false, a character, a
 * `sizeof`, an error-code macro, an enumerator, a function-like macro over
 * constants that calls nothing, or a brace list of them. Each is
 * overwritten before any read on every path, through branches, a `goto`
 * and a loop. One read on some path, or in the overwrite's own right-hand
 * side, keeps the initializer live in any case.
 */

#include <stdbool.h>
#include <stddef.h>

#define ERR_CORRUPTED -0x006E
#define MKERR(n) (-(n))

enum status { STATUS_UNSET = -2, STATUS_OK = 0 };

struct pair {
    int a;
    int b;
};

int get(void);
char *name(void);
bool ready(void);
struct pair make(void);

int zero_then_computed(int c)
{
    int x = 0;
    x = c * 2;
    return x;
}

int minus_one_on_both_branches(int c)
{
    int r = -1;
    if (c)
        r = get();
    else
        r = 2;
    return r;
}

char *null_pointer(void)
{
    char *p = NULL;
    p = name();
    return p;
}

char *null_cast(void)
{
    char *p = (void *)0;
    p = name();
    return p;
}

int false_flag(void)
{
    bool ok = false;
    ok = ready();
    return ok;
}

int error_code_macro(void)
{
    int r = ERR_CORRUPTED;
    r = get();
    return r;
}

int constant_macro_call(void)
{
    int r = MKERR(5);
    r = get();
    return r;
}

int enumerator(void)
{
    enum status s = STATUS_UNSET;
    s = get() ? STATUS_OK : STATUS_UNSET;
    return s;
}

unsigned size_constant(unsigned c)
{
    unsigned n = sizeof(int) * 2;
    n = c;
    return n;
}

char character(int c)
{
    char ch = '?';
    ch = (char)c;
    return ch;
}

int brace_list(void)
{
    struct pair v = {0};
    v = make();
    return v.a;
}

int through_goto(void)
{
    int r = -1;
    r = get();
    if (r)
        goto out;
    r = 0;
out:
    return r;
}

int through_loop(int n)
{
    int i = 0;
    int sum = 0;
    for (i = 1; i < n; i++)
        sum += i;
    return sum;
}

int read_on_one_path(int c)
{
    int x = 0;
    if (c)
        x = 1;
    return x;
}

int read_by_the_overwrite(int c)
{
    int x = 0;
    x = x + c;
    return x;
}
