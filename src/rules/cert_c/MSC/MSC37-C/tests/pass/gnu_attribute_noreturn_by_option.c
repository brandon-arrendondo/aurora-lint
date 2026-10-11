/*
 * Rule: MSC37-C
 * Source: synthetic (the shape of CERT's EX2, with the GNU spelling)
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 *
 * `fatal` is declared with the GNU noreturn attribute. The default preset
 * credits a call to it as ending the path, as it does _Noreturn (the
 * `msc37_attribute_noreturn` option); strict and pedantic accept only the ISO
 * spellings, so control may fall off the end.
 */

void fatal(const char *message) __attribute__((noreturn));

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fatal("bad token");
}
