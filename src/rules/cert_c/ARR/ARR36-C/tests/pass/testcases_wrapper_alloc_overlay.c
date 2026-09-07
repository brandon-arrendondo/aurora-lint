/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: Same overlay argument as tests/pass/testcases_overlay_struct_in_buffer.c,
 *         but the object comes from an allocator WRAPPER rather than a buffer:
 *         'mgmt = os_zalloc(sizeof(*mgmt))' and then two field paths rooted at
 *         mgmt. Both operands are members of ONE allocated object, so the
 *         subtraction walks one object twice.
 *
 *         This needs 'zalloc' in the allocation arm of extract_array_base to
 *         pass. Without it os_zalloc canonicalizes to a name outside the list,
 *         mgmt gets NO base at all, and the two field paths stay two whole
 *         paths -- distinct, and reported. Distilled from hostap
 *         src/ap/wnm_ap.c::ieee802_11_send_bss_trans_mgmt_request.
 */

#include <stddef.h>

void *os_zalloc(size_t size);
char *os_strdup(const char *s);

struct action_body {
    unsigned char category;
    unsigned char action;
    unsigned char variable[];
};

struct mgmt_frame {
    unsigned char da[6];
    struct action_body u;
};

/* Two members of one os_zalloc'd object. */
size_t bss_trans_mgmt_len(void)
{
    struct mgmt_frame *mgmt;
    unsigned char *pos;

    mgmt = os_zalloc(sizeof(*mgmt) + 32);
    if (mgmt == NULL) {
        return 0;
    }

    pos = mgmt->u.variable;
    *pos++ = 0;

    return (size_t)(pos - &mgmt->u.category);
}

/* A cursor walking one os_strdup'd string is still inside it. */
size_t dup_len(const char *in)
{
    char *copy;
    char *p;

    copy = os_strdup(in);
    if (copy == NULL) {
        return 0;
    }

    p = copy;
    while (*p) {
        p++;
    }

    return (size_t)(p - copy);
}
