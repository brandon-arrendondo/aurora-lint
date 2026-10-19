/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * MSC13-EX1: a macro whose replacement list invokes other macros that
 * only compute constants (`BUFSZ` over `KB(4)`, `MASK` over `BITV(n)`),
 * or `offsetof`, is as much a default as the constant written out. Each
 * initializer is overwritten before any read on every path.
 */

#include <stddef.h>

#define KB(x) ((x) * 1024)
#define BUFSZ KB(4)
#define BITV(n) (1u << (n))
#define MASK ((unsigned)(BITV(0) | BITV(1)))
#define MKERR(n) (-(n))
#define MKERR2(n) MKERR(n)

struct pair {
    int a;
    int b;
};

#define B_OFFSET offsetof(struct pair, b)

int get(void);

int buffer_size(void)
{
    int n = BUFSZ;
    n = get();
    return n;
}

unsigned mask(void)
{
    unsigned m = MASK;
    m = (unsigned)get();
    return m;
}

int nested_error(void)
{
    int r = MKERR2(5);
    r = get();
    return r;
}

size_t offset(void)
{
    size_t o = B_OFFSET;
    o = (size_t)get();
    return o;
}

size_t direct_offset(void)
{
    size_t o = offsetof(struct pair, b);
    o = (size_t)get();
    return o;
}
