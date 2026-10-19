/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: PASS - the macro reads the enumerator width; the parameter of the same name belongs to another function, so where the macro is expanded its value is a constant default
 */

enum { width = 8 };

#define ROW_BYTES (width * 4)

int get(void);

int scale(int width)
{
    return width * 2;
}

int row(void)
{
    int n = ROW_BYTES;
    n = get();
    return n;
}
