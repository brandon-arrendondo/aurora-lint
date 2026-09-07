/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: A field path rooted at a pointer this frame never resolved is not a
 *         different object from that pointer. `extract_array_base` hands an
 *         untracked pointer's raw NAME back as a base (task 962), so leaving
 *         the path whole spells one object two ways -- 'mgmt' and
 *         'mgmt->u.req.variable' -- and the pair reads as two arrays.
 *
 *         Distilled from hostap src/ap/wnm_ap.c: 'mgmt = os_zalloc(...)' is an
 *         allocation this frame cannot see into, so nothing is recorded for
 *         mgmt, and 'pos - &mgmt->u.action.category' then compares two
 *         spellings of the one allocation.
 */

#include <stddef.h>

struct action_body {
    unsigned char category;
    unsigned char action;
    unsigned char variable[];
};

struct frame {
    unsigned char da[6];
    struct {
        struct action_body req;
    } u;
};

extern void *opaque_alloc(size_t n);

size_t build_request(void)
{
    struct frame *mgmt;
    unsigned char *pos;

    mgmt = opaque_alloc(sizeof(*mgmt));
    if (mgmt == NULL) {
        return 0;
    }

    mgmt->u.req.category = 10;
    pos = mgmt->u.req.variable;

    return (size_t) (pos - &mgmt->u.req.category);
}

int main(void)
{
    return (int) build_request();
}
