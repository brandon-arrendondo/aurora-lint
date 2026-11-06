/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - A macro that reads a const object sizes a VLA
 * Expect: count=2
 *
 * A macro is what its replacement list is where it is used. One that
 * names a `static const` object, or an object-like macro whose own body
 * reads a local, is not an integer constant expression (C11 6.6), so each
 * array is variable-length, whatever the names are spelled like.
 */
static const int LIMIT = 8;
#define TWICE_LIMIT (LIMIT * 2)
#define CURRENT (len)

void sink(char *p);

void runtime_sizes(int len)
{
    char through_const[TWICE_LIMIT];
    char through_local[CURRENT + 1];
    sink(through_const);
    sink(through_local);
}
