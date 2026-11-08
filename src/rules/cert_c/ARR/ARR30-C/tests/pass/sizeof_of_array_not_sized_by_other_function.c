/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - `sizeof(buf) - 1` is this function's `buf`
 *
 * The other function's array has another size, and is another object.
 */

void other(void)
{
    char buf[32];
    buf[0] = 1;
}

int element(void)
{
    char buf[8];
    return buf[sizeof(buf) - 1];
}
