/*
 * Rule: DCL30-C
 * Status: FAIL - Should trigger DCL30-C violation
 * Reason: A local pointer is reported for what it holds. Each pointer here
 *         holds, on every path to the escape, the address of an automatic
 *         object: an element of a local array, a copy of a copy of one, and
 *         a parameter reassigned to a local buffer.
 */

char *element_of_local_array(void)
{
    char charString[] = "a string";
    char *ptrCharString;
    ptrCharString = &charString[1];
    return ptrCharString;   /* VIOLATION */
}

char *copied_twice(void)
{
    char buf[16];
    char *q = buf;
    char *p = q;
    return p;               /* VIOLATION */
}

char *reassigned_parameter(char *in)
{
    char buf[16];
    in = buf;
    return in;              /* VIOLATION */
}
