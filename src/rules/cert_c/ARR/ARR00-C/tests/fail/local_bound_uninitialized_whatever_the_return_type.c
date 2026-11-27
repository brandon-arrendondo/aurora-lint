/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: FAIL - A local loop bound is never given a value in functions returning a pointer, a pointer to a pointer and a function pointer
 * Expect: count=4
 *
 * Each function has a parameter, but the loop is bounded by a local that is
 * declared without a value and never assigned. Finding the function's own
 * parameter list must not make every name in the function a parameter.
 */
static char row[16];
static char *rows[16];

static int use(double x) { return (int)x; }

int fill_returning_int(int n)
{
    int i, m;
    for (i = 0; i < m; i++) { /* Expect: here */
        row[i] = 0;
    }
    return n;
}

char *fill_returning_a_pointer(int n)
{
    int i, m;
    for (i = 0; i < m; i++) { /* Expect: here */
        row[i] = (char)n;
    }
    return row;
}

char **fill_returning_a_pointer_to_a_pointer(int n)
{
    int i, m;
    for (i = 0; i < m; i++) { /* Expect: here */
        rows[i] = row + n;
    }
    return rows;
}

int (*fill_returning_a_function_pointer(int n))(double)
{
    int i, m;
    for (i = 0; i < m; i++) { /* Expect: here */
        row[i] = (char)n;
    }
    return use;
}
