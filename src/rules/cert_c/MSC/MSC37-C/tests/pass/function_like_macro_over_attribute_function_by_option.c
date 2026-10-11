/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's EX2, with the GNU spelling)
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * `fail(s)` is a function-like macro whose every definition is a call to a
 * function declared noreturn by the GNU attribute, so using it ends the
 * path.
 */

#define NORETURN __attribute__((__noreturn__))

void halt(void) NORETURN;
void report_and_halt(const char *s, const char *file, int line) NORETURN;

#ifdef DEBUG_BUILD
#define fail(s) report_and_halt(s, __FILE__, __LINE__)
#else
#define fail(s) halt()
#endif

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fail("bad token");
}
