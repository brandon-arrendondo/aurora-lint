/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: A struct pointer cast from a buffer overlays that buffer, so a
 *         member reached through it -- a flexible array member included -- is
 *         storage INSIDE the buffer the other operand walks, not a second
 *         array. Distilled from hostap: wnm_ap.c and rrm.c both do
 *         'mgmt = (struct ieee80211_mgmt *) buf', take
 *         'pos = mgmt->u.action.u.<x>.variable', and then measure the frame
 *         with 'pos - buf'.
 *
 *         The member really is storage -- it is a flexible array member, not
 *         a pointer, so the pointer-vs-array member test in
 *         tests/pass/testcases_struct_pointer_members.c correctly leaves it
 *         naming storage. What settles it is the ROOT: this frame watched
 *         'mgmt' be assigned from 'buf'.
 */

#include <stddef.h>

struct frame_body {
    unsigned char category;
    unsigned char action;
    unsigned char variable[];
};

struct frame {
    unsigned char da[6];
    unsigned char sa[6];
    struct frame_body body;
};

/* The cast, the member and the subtraction all in one frame. */
size_t build_local(void)
{
    unsigned char buf[256];
    unsigned char *pos;
    struct frame *f;

    f = (struct frame *) buf;
    f->body.category = 10;
    f->body.action = 7;

    pos = f->body.variable;
    *pos++ = 0;

    return (size_t)(pos - buf);
}

/* The buffer arrives as a parameter; the overlay is still local. */
size_t measure_incoming(unsigned char *buf, size_t len)
{
    const struct frame *f = (const struct frame *) buf;
    const unsigned char *pos;
    const unsigned char *end;

    end = buf + len;
    pos = f->body.variable;

    if (pos > end) {
        return 0;
    }
    return (size_t)(end - pos);
}

/* Two members of one overlay: both are inside the same object. */
size_t header_length(unsigned char *buf)
{
    struct frame *f = (struct frame *) buf;

    return (size_t)(f->body.variable - &f->body.category);
}
