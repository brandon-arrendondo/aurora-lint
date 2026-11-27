/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: PASS - A parameter bounds a loop in functions returning a pointer, a pointer to a pointer and a function pointer
 *
 * A parameter is initialized to its argument's value on entry, so a loop
 * bounded by one does not read an uninitialized variable. The return type
 * does not change which parameter list is the function's own: in
 * `int (*pick(int n))(double)` it is `(int n)`, not the `(double)` of the
 * function pointer returned. The plain `int` function is the control.
 */
static char row[16];
static char *rows[16];

static int use(double x) { return (int)x; }

int fill_returning_int(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        row[i] = 0;
    }
    return n;
}

char *fill_returning_a_pointer(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        row[i] = 0;
    }
    return row;
}

char **fill_returning_a_pointer_to_a_pointer(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        rows[i] = row;
    }
    return rows;
}

int (*fill_returning_a_function_pointer(int n))(double)
{
    int i;
    for (i = 0; i < n; i++) {
        row[i] = 0;
    }
    return use;
}
