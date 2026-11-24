/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A count macro bounds an index only where every definition of it is a count
 * Expect: count=2
 *
 * Without `WIDE_COUNT`, `ARRAY_SIZE(tbl)` is `sizeof(tbl)`, 16 bytes, so
 * the guard leaves `i` up to 15 against 4 elements. After the `#undef`,
 * `COUNT(tbl)` is the same byte size. Neither guard bounds the index.
 */

#ifdef WIDE_COUNT
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#else
#define ARRAY_SIZE(a) (sizeof(a))
#endif

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#undef COUNT
#define COUNT(a) (sizeof(a))

extern unsigned next_index(void);

static int tbl[4];

int in_arms(void)
{
    unsigned i = next_index();
    if (i >= ARRAY_SIZE(tbl))
        return 0;
    return tbl[i]; /* Expect: here */
}

int after_undef(void)
{
    unsigned i = next_index();
    if (i >= COUNT(tbl))
        return 0;
    return tbl[i]; /* Expect: here */
}
