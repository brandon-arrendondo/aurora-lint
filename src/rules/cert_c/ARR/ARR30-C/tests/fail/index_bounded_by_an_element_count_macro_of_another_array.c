/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An element count bounds only the array it counts
 * Expect: count=2
 *
 * `ARRAY_SIZE(wide)` is 8, so the guard leaves `i` up to 7 against
 * `narrow`'s 4 elements. `ARRAY_SIZE(name)` counts nothing: `name` is a
 * pointer, so the quotient is the width of a pointer over that of a
 * `char`, not an element count of `table`.
 */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

extern unsigned next_index(void);

static int wide[8];
static int narrow[4];
static int table[4];

int pick(void)
{
    unsigned i = next_index();

    if (i >= ARRAY_SIZE(wide))
        return 0;
    return wide[i] + narrow[i]; /* Expect: here */
}

int lookup(const char *name)
{
    unsigned i = next_index();

    if (i >= ARRAY_SIZE(name))
        return 0;
    return table[i] + name[0]; /* Expect: here */
}
