/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * One definition of `fail` calls a function that returns, so using the macro
 * does not end the path in every configuration.
 */

#define NORETURN __attribute__((__noreturn__))

void halt(void) NORETURN;
void report(const char *s);

#ifdef DEBUG_BUILD
#define fail(s) report(s)
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
