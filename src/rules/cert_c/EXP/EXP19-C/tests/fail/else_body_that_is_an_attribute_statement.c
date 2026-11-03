/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: The else body is a null statement carrying a GNU attribute,
 * not a brace-enclosed block. `else` is a keyword, not a declarator, so the
 * parser's repair of an attribute written after a declarator must leave this
 * statement as written; moved in front of `else`, the attribute would hide
 * the unbraced body.
 * Expect: count=1
 */

int step(int x)
{
    switch (x) {
    case 1:
        if (x > 0) {
            x++;
        } else __attribute__((fallthrough)); /* Expect: here */
    default:
        break;
    }
    return x;
}
