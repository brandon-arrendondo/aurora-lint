/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - the only other occurrences of the name are a local object of that name
 */
static int count(void) /* Expect: here */
{
    return 3;
}

int api(int v)
{
    int count = v;
    count++;
    return count;
}
