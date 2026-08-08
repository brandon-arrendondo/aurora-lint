/*
 * Rule: EXP36-C
 * Source: hostap ground-truth audit (task 159 adversarial pass) / task 395
 * Status: FAIL - Should trigger EXP36-C violation
 * Regression: a struct with no packed attribute at all should still be
 * flagged when cast from a less-aligned pointer -- guards against the
 * packed-struct fix over-suppressing genuine violations.
 */

struct nlattr {
    unsigned short nla_len;
    unsigned short nla_type;
};

void parse_attr(unsigned char *data) {
    struct nlattr *attr = (struct nlattr *) data;
    (void)attr;
}
