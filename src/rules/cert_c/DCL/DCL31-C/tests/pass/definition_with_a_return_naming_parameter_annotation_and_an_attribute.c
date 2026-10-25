/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: A function definition whose parameter carries an annotation
 * macro naming `return` (OUT_TO(n, return) below), with an attribute
 * between its parameter list and its body. Only the annotation is blanked,
 * so the definition keeps its name and the later call is to a declared
 * function.
 */

static int copy_out(OUT_TO(n, return) char *b, int n) __attribute__((noinline))
{
    if (n > 0) {
        b[0] = 'x';
    }
    return n;
}

int use(void)
{
    char buf[4];
    return copy_out(buf, 4);
}
