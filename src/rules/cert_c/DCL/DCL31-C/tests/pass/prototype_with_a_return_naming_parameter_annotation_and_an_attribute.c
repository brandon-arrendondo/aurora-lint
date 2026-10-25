/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: A parameter can carry an annotation macro whose argument
 * names `return` (OUT_TO(n, return) below), defined in a header this file
 * does not show. The annotation is blanked before the file is read, and
 * only the annotation: the prototype around it is kept whatever follows
 * its parameter list, here an attribute, so the calls are to a declared
 * function.
 */

int fill(OUT_TO(n, return) char *buf, int n) __attribute__((nonnull));

int use(void)
{
    char buf[8];
    int got = fill(buf, 8);
    return got + fill(buf, 4);
}
