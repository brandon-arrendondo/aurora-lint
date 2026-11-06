/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - A macro over a runtime value, or a function call, sizes a VLA
 * Expect: count=2
 *
 * A function-like macro is what its replacement list is with its
 * arguments in place: `TWICE(n)` reads the parameter `n`. A call of a
 * function this file declares is evaluated at run time. Neither is an
 * integer constant expression (C11 6.6), so each array is variable-length.
 */
#define TWICE(x) ((x) * 2)

unsigned long buffer_size(void);
void sink(void *p);

void runtime_sizes(int n)
{
    char doubled[TWICE(n)];
    char by_call[buffer_size()];
    sink(doubled);
    sink(by_call);
}
