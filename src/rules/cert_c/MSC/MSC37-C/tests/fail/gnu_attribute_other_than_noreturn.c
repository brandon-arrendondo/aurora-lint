/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * An attribute that is not noreturn does not end the path.
 */

void log_failure(const char *message) __attribute__((format(printf, 1, 2)));

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    log_failure("bad token");
}
