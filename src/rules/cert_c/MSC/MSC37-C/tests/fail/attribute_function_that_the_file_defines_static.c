/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: FAIL under every preset
 *
 * A call reaches the file's own `static` function, which returns, not
 * a same-named function declared noreturn elsewhere.
 */

static void fatal(const char *message)
{
    (void)message;
}

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    fatal("bad token");
}
