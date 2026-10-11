/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 * Settings: msc37_attribute_noreturn=false
 *
 * With `msc37_attribute_noreturn` off, a call to a function declared noreturn
 * only by the GNU attribute does not end the path.
 */

void fatal(const char *message) __attribute__((noreturn));

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fatal("bad token");
}
