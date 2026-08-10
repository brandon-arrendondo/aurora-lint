/*
 * Rule: EXP30-C
 * Source: regression (real-world FP: netlink-style alloc-and-check pattern)
 * Status: PASS - Should NOT trigger EXP30-C violation
 *
 * `&&` and `||` are sequence points (C11 6.5.13, 6.5.14): the right operand
 * is only evaluated after the left, with a sequence point in between. So
 * assigning `msg` on the left of `||` and reading it on the right is
 * well-defined -- this is not an unsequenced modification/access of `msg`.
 */

#include <stddef.h>

struct nl_msg;
struct nl_msg *nlmsg_alloc(void);
int nla_put_u32(struct nl_msg *msg, int attr, unsigned int value);
int nla_put(struct nl_msg *msg, int attr, size_t len, const void *data);

int send_attrs(int attr1, unsigned int val, int attr2, size_t len, const void *data) {
  struct nl_msg *msg;

  if (!(msg = nlmsg_alloc()) || nla_put_u32(msg, attr1, val) ||
      nla_put(msg, attr2, len, data)) {
    return -1;
  }

  return 0;
}
