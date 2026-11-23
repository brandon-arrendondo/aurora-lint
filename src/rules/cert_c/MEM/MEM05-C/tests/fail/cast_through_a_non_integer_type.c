/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - A cast to a non-integer type is not an integer constant
 * Expect: count=3
 *
 * Only a cast to an integer type may appear in an integer constant
 * expression (C11 6.6p6). A size that passes through a cast to a floating
 * type, to a pointer type or to a floating typedef is not one, so each
 * array is variable-length.
 */
typedef double ratio_t;

void sink(char *p);

void runtime_sizes(void)
{
    char by_float[(int)(float)4];
    char by_pointer[(long)(char *)8];
    char by_typedef[(int)(ratio_t)2];
    sink(by_float);
    sink(by_pointer);
    sink(by_typedef);
}
