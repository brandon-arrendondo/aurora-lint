/*
 * Rule: ARR32-C
 * Source: synthetic
 * Status: FAIL - A size read from an object is a VLA, however it is spelled
 * Expect: count=3
 *
 * C has no named integer constants other than enumerators and macros: an
 * object is not an integer constant expression (C11 6.6), `const` or not,
 * so each array is variable-length. That holds for an ALL_CAPS `const`,
 * a macro whose replacement list reads a `static const`, and a sum that
 * reads a parameter.
 */
static const int LIMIT = 8;
#define TWICE_LIMIT (LIMIT * 2)

void sink(char *p);

void runtime_sizes(int n)
{
    const int SZ = 32;
    char by_const[SZ + 1];
    char through_macro[TWICE_LIMIT + 1];
    char by_parameter[n + 1];
    sink(by_const);
    sink(through_macro);
    sink(by_parameter);
}
