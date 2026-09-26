/*
 * Rule: PRE30-C
 * Source: real-world FP pattern (hostap, lua)
 * Status: PASS - Should NOT trigger PRE30-C violation
 *
 * buf_concat and str_join are ordinary functions: nothing defines either
 * as a macro. A function call cannot paste its arguments into a universal
 * character name, whatever the callee is called and however the arguments
 * look.
 */

struct buf;

void buf_concat(struct buf *b, int flags);
const char *str_join(const char *head, const char *tail);

void build(struct buf *b)
{
    buf_concat(b, 01);
    (void)str_join("\\u00", "E9");
}
