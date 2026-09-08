/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: Parentheses are not an object. A cursor set from '(buf + 4)' has to
 *         record the same base a bare 'buf + 4' records, or it records
 *         NOTHING and every subtraction below it goes unmeasured.
 *
 *         Distilled from hostap src/ap/fils_hlp.c, where 'pos = (u8 *)
 *         (dhcp + 1)' recorded no base, so a later 'end_opt = pos' kept the
 *         raw name 'pos' and compared it against 'buf' -- one object spelled
 *         two ways.
 *
 *         The alias is load-bearing: without it the operand simply has no
 *         base and get_pointer_info returns None. The FP needs STORAGE on the
 *         other side, which is why 'buf' is an array here rather than a
 *         parameter -- against a parameter the UntrackedPointer gate
 *         neutralises the raw-name path and this passes even before the fix.
 */

#include <stddef.h>

ptrdiff_t cursor_from_paren(void)
{
    unsigned char buf[64];
    unsigned char *pos = (unsigned char *) (buf + 4);
    unsigned char *mark;

    mark = pos;

    return mark - buf;
}

ptrdiff_t cursor_from_nested_paren(void)
{
    unsigned char buf[64];
    unsigned char *pos = (unsigned char *) ((buf + 4));
    unsigned char *mark;

    mark = pos;

    return mark - buf;
}

int main(void)
{
    return (int) (cursor_from_paren() + cursor_from_nested_paren());
}
