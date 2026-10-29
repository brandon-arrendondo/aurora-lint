/*
 * Rule: MSC37-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC37-C violation
 * Description: An #if 0 block that ends in a control header holds every
 * header that header is the body of too (`if (a)` / `if (b)`, `for (;;)` /
 * `while (a)`), and none of them is in any build. So each brace block after
 * an #endif is a plain compound statement, and each function ends in its
 * return. Code before a header on its own line (`b); if (a)`) is not part of
 * the header and changes nothing.
 */

void g(int a, int b);

int nested_ifs(int a, int b)
{
#if 0
    if (a)
        if (b)
#endif
    { return b; }
}

int loops(int a, int b)
{
#if 0
    for (;;)
        while (a)
#endif
    { return b; }
}

int header_after_a_call(int a, int b)
{
#if 0
    g(a,
      b); if (a)
#endif
    { return b; }
}
