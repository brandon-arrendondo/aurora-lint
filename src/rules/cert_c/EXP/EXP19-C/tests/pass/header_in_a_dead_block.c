/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: A control header alone in a block the file proves is never
 * compiled (#if 0). No build has the header, so the live statement after
 * the #endif is no statement's body.
 */

int dead_if(int a, int b)
{
#if 0
    if (a)
#endif
    b++;
    return b;
}

int dead_while(int a, int b)
{
#if 0
    while (a--)
#endif
    b++;
    return b;
}

int two_dead_headers(int a, int b)
{
#if 0
    if (a)
#endif
    { b++; }
#if 0
    while (a--)
#endif
    b--;
    return b;
}
