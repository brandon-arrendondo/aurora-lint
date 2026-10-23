/*
 * Rule: PRE01-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE01-C violation
 *
 * Every unparenthesized use of a parameter is reported, each where it is
 * written, including on a continued line. `T * x` is a declaration or a
 * multiplication depending on the argument, so it stays reported.
 */

#define SUM3(a, b, c) (a + b + \
                       c * 2)
#define MAYBE_DECL(T, x) T * x

int main(void) {
    int y = 3;
    int z = SUM3(1, 2, 3);
    return z + MAYBE_DECL(y, 2);
}
