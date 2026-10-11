/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's EX2, with the GNU spelling)
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * The attribute may lead the declaration, and may sit among others in its
 * list.
 */

__attribute__((cold, __noreturn__)) void fatal(const char *message);

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fatal("bad token");
}
