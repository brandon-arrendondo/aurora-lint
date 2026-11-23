/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A parameter declared as an array is a pointer
 *
 * sizeof(b) is the size of a char pointer, not 16, so the index is not
 * 15 and no constant is claimed for it.
 */

int element(char b[16])
{
    char a[10] = {0};
    return a[sizeof(b) - 1] + b[0];
}
