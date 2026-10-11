/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - Pointers that held a literal are repointed before any write
 *
 * Assigning a new literal to an array element changes the element, not a
 * literal; and a pointer reassigned on every path to a buffer writes into
 * the buffer.
 */

void func(char *buf)
{
    char *arr[] = { "a", "b" };
    arr[1] = "c";

    char *p = "x";
    p = buf;
    p[0] = 'k';
}
