/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's EX2, with the GNU spelling)
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * `NORETURN` is a macro defined as the GNU attribute, so a function declared
 * with it is noreturn: the definition decides, not the spelling.
 */

#define NORETURN __attribute__((__noreturn__))

void halt(void) NORETURN;

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    halt();
}
