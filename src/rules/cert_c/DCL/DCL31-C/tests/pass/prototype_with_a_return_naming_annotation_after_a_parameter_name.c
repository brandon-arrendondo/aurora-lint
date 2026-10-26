/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: An annotation macro whose argument names `return` can follow
 * a parameter's name (OUT_TO(n, return) below), defined in a header this
 * file does not show, and an unknown macro can follow the parameter list.
 * The annotation is blanked before the file is read, and only the
 * annotation: the prototype around it is kept, so the call is to a
 * declared function.
 */

int fill_tail(int n, char *buf OUT_TO(n, return)) NOTHROW;

int use(void)
{
    char buf[4];
    return fill_tail(4, buf);
}
