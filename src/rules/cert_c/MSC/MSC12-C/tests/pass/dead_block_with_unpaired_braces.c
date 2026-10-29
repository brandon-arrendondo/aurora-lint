/*
 * Rule: MSC12-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC12-C violation
 * Description: An #if 0 block whose own braces do not pair up (it closes
 * the live `if (x) {` and opens a header of its own) is never compiled, so
 * the live `if` still governs a(), and its body is not empty.
 */

void a(void);
void b(void);

void f(int x)
{
    if (x) {
#if 0
        }
        if (x)
#endif
        a();
    }
    b();
}
