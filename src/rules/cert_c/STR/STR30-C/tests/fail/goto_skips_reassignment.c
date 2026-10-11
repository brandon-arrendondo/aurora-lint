/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - The goto skips the reassignment, so p still points at the
 * literal when it is written
 */

void mark(int c, char *buf)
{
    char *p = "lit";
    if (c)
        goto write;
    p = buf;
write:
    p[0] = 'x';
}
