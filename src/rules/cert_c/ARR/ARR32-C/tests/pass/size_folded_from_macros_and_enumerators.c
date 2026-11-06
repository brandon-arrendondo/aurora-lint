/*
 * Rule: ARR32-C
 * Source: synthetic
 * Status: PASS - Each size is an integer constant expression, so no array is a VLA
 *
 * A size built from macros and enumerators is a constant (C11 6.6)
 * whatever the names are spelled like: an ALL_CAPS macro, a lower-case
 * one, an enumerator, a shift, and a macro whose replacement list names
 * an enumerator.
 */
#define N 16
#define bufsize 64
#define SLOTS_TWICE (2 * slots)

enum { slots = 8 };

void sink(char *p);

void fixed_sizes(void)
{
    char doubled[N * 2];
    char lower[bufsize + 1];
    char by_enumerator[slots * 4];
    char shifted[1 << 12];
    char through_macro[SLOTS_TWICE + 1];
    sink(doubled);
    sink(lower);
    sink(by_enumerator);
    sink(shifted);
    sink(through_macro);
}
