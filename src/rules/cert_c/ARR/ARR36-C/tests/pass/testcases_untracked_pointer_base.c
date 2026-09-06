/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: A declared pointer whose target this frame never learned does not
 *         name an array, so it cannot be one side of "two different arrays".
 *         Distilled from hostap src/common/dpp_backup.c: `pos = hdr.payload`
 *         gives pos a pointer-member base, `end = next` gives end the raw
 *         base `next`, and the pair was reported as spanning two arrays --
 *         but what `next` points at is unknown, not known-distinct.
 */

#include <stddef.h>

struct chunk {
    const unsigned char *payload;
    size_t length;
};

extern const unsigned char *opaque_next(struct chunk *hdr);

int walk(struct chunk *hdr)
{
    /* Assigned from a call this frame cannot see into, so no base is known. */
    const unsigned char *next = opaque_next(hdr);
    const unsigned char *pos;
    const unsigned char *end;

    pos = hdr->payload;
    end = next;

    /* A pointer member against an untracked pointer: neither names storage. */
    if (pos < end) {
        return 1;
    }
    return 0;
}
