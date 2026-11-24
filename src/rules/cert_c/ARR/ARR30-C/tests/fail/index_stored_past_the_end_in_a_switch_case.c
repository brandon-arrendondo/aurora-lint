/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A switch's cases are ways to the access
 * Expect: count=2
 *
 * In `fall_through`, entering at `case 2` skips the store of 0, so `i` is
 * still 9 at the access. In `after_switch`, case 1 leaves `i` at 9.
 */

int fall_through(int c)
{
    int buf[5] = {0};
    int i = 9;
    switch (c) {
    case 1:
        i = 0;
    case 2:
        return buf[i]; /* Expect: here */
    }
    return 0;
}

int after_switch(int c)
{
    int buf[5] = {0};
    int i = 0;
    switch (c) {
    case 1:
        i = 9;
        break;
    case 2:
        i = 1;
        break;
    }
    return buf[i]; /* Expect: here */
}
