/*
 * Rule: API05-C
 * Source: hand-authored (task 194 -- see below)
 * Status: PASS - Should NOT trigger API05-C violation
 *
 * CERT's own wiki page for API05-C never demonstrates the `[static N]` form
 * of a conformant array parameter (C11 Sec 6.7.6.3p7) -- its compliant
 * examples only use the plain `a[n]` / `a[*]` forms. `[static N]` is the
 * STRONGEST conformance signal API05-C's own description talks about
 * (guarantees the caller passes an array of at least N elements, letting
 * the compiler validate/optimize on that guarantee), yet task 217's
 * real-world idiom survey across 11 local repos + raylib + monocypher
 * found ZERO genuine uses of it anywhere -- the only hit was a
 * documentation comment in newlib's cdefs.h. No real-world codebase can
 * ever supply a positive-validation TP for this specific syntax, so this
 * is the synthetic fixture task 194 calls for: a hand-written, fully
 * controlled example confirming the rule recognizes `[static N]` as
 * compliant rather than silently never exercising that code path.
 */

#include <stddef.h>

void my_memset(size_t n, char p[static n], char v)
{
    for (size_t i = 0; i < n; i++)
    {
        p[i] = v;
    }
}
