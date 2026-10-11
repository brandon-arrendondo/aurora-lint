/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's EX2, with the GNU spelling)
 * Status: PASS under every preset with the option set on
 * Settings: msc37_attribute_noreturn=true
 * Expect: default=clean strict=clean pedantic=clean
 *
 * The option is set on explicitly, so every preset credits the
 * attribute too.
 */

void fatal(const char *message) __attribute__((noreturn));

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fatal("bad token");
}
