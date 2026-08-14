/*
 * Rule: DCL00-C
 * Status: PASS - Should NOT trigger DCL00-C violation
 */

/*
 * Reason (task 391, hostap's authsrv.c): `username` is genuinely written
 * via `radius_msg_get_attr(msg, ATTR, (u8 *) username, sizeof(username) -
 * 1)` -- an out-param write through a cast of the bare array (arrays
 * decay to a pointer on their own, no `&` needed), with no other
 * assignment anywhere in scope. Previously only an explicit `&var` counted
 * as evidence of possible mutation through a pointer, so an array passed
 * bare (or cast) to an unknown out-param function was wrongly recommended
 * for const-qualification.
 */

typedef unsigned char u8;
struct radius_msg;
int radius_msg_get_attr(struct radius_msg *msg, unsigned int attr, u8 *buf,
                        unsigned long len);

void parse(struct radius_msg *msg)
{
    char username[64] = "";

    radius_msg_get_attr(msg, 1, (u8 *) username, sizeof(username) - 1);
}
