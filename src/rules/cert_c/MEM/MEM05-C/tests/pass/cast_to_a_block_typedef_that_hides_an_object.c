/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - a cast to a block typedef that hides an object
 *
 * Inside the function, `len` is the typedef, though a file-scope object of
 * that name encloses it (C11 6.2.1p4), so `(len)4` is a cast to unsigned
 * and the size is a constant.
 */
int len = 4;

void sink(char *p);

void fixed_size(void)
{
    typedef unsigned len;
    char by_typedef[(len)4];
    sink(by_typedef);
}
