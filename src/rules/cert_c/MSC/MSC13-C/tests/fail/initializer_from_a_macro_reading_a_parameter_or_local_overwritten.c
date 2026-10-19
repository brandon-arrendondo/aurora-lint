/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - a macro whose body reads a parameter or a local of the function it is expanded in yields that object's value, not a default, directly or through another macro
 */

struct pair {
    int a;
    int b;
};

int get(void);
const char *next_name(void);
struct pair make(void);

#define CURRENT_CHAR (*z)
#define FIRST_VALUE (values[0])
#define OFFSET(i) (base + (i))
#define PIVOT { v, 0 }
#define LIMIT (count * 2)
#define DOUBLE_LIMIT (LIMIT + LIMIT)

int current(const char *z)
{
    int c = CURRENT_CHAR;
    c = get();
    return c + *z;
}

const char *first(const char **values)
{
    const char *f = FIRST_VALUE;
    f = next_name();
    return f;
}

int offset(int base)
{
    int r = OFFSET(2);
    r = get();
    return r + base;
}

int pivot(int v)
{
    struct pair p = PIVOT;
    p = make();
    return p.a + v;
}

int limit(void)
{
    int count = get();
    int n = DOUBLE_LIMIT;
    n = get();
    return n + count;
}
