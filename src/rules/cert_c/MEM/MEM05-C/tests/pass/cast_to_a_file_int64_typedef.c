/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - a cast to a file typedef of __int64
 *
 * `__int64` is an integer type, so `(i64)4` is a constant size.
 */
typedef __int64 i64;

void sink(char *p);

void fixed_size(void)
{
    char by_typedef[(i64)4];
    sink(by_typedef);
}
