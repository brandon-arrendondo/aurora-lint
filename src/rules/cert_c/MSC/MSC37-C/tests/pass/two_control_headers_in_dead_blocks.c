/*
 * Rule: MSC37-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC37-C violation
 * Description: Two blocks the file proves are never compiled (#if 0) in
 * one function, each holding only a control header. No build has either
 * header, so each brace block after an #endif is a plain compound
 * statement and the function ends in its return.
 */

void a(void);
void b(void);

int f(int p)
{
#if 0
    if (p)
#endif
    { a(); }
#if 0
    while (p)
#endif
    { b(); }
    return 0;
}
