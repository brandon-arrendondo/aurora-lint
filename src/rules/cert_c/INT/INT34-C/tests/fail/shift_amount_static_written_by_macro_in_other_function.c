/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A macro another function uses assigns the static amount
 *
 * `other` assigns `s` through `SET`, and `refresh` may call it, so the
 * shift may be by 40.
 */

#define SET(v) (s = (v))

static int s;

void other(void)
{
    SET(40);
}

void refresh(void);

int mask(void)
{
    s = 3;
    refresh();
    return 1 << s;
}
