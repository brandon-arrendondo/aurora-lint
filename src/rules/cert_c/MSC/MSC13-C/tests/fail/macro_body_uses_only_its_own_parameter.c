/*
 * Rule: MSC13-C
 * Status: FAIL - a macro whose replacement list mentions a name only as its
 * own PARAMETER says nothing about a caller-scope variable that happens to
 * share that name. `SQUARE(x)` binds `x` itself, so the local `x` here is
 * still genuinely unused (task 756: the macro-hidden-use check must key on
 * FREE identifiers, not on any token in the body).
 */

#define SQUARE(x) ((x) * (x))

int f(int n)
{
    int x = 5;      /* VIOLATION: never read; SQUARE's `x` is its parameter */
    return SQUARE(n);
}
