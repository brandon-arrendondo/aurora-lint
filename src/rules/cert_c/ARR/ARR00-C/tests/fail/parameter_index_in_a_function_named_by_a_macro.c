/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: FAIL - A parameter indexes an array without a bounds check in a function whose name a macro builds
 * Expect: count=1
 *
 * `SUFFIX (put_section) (struct layout *smd, int i)` reads as a name applied
 * to two parameter lists. C has no function returning a function, so the
 * first list is the macro's argument and the second is the function's own,
 * which makes `i` a parameter used as an unchecked index.
 */
#define SUFFIX(x) x##_64

struct layout {
    int addrs[8];
};

static int SUFFIX (put_section) (struct layout *smd, int i)
{
    smd->addrs[i] = 0; /* Expect: here */
    return 0;
}
