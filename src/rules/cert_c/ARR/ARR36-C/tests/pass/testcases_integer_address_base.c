/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: An INTEGER holding a converted address does not name an array. The
 *         base of `a + b` was taken from the left operand's name with no check
 *         that the name is a pointer at all, so 'behind_tag' -- declared
 *         `word_t` -- was recorded as a base; it is neither a declared pointer
 *         (which would make it an untracked pointer, task 962) nor a declared
 *         array, so it then read as STORAGE and was compared against a real
 *         object.
 *
 *         Distilled from seL4 src/arch/x86/kernel/boot_sys.c, which converts a
 *         multiboot tag's address into a `word_t`, adds a byte offset, and
 *         casts the result back.
 *
 *         The address of a non-pointer scalar is still storage: '&count' has
 *         to keep naming an object, which is why only the ARITHMETIC operand
 *         is read this way.
 */

#include <stddef.h>

typedef unsigned long word_t;

struct region {
    unsigned long addr;
    unsigned long size;
};

struct tag {
    unsigned long type;
    unsigned long size;
};

size_t region_span(const struct tag *tag)
{
    word_t const behind_tag = (word_t) tag + sizeof(*tag);
    const struct region *s = (const struct region *) behind_tag + 1;
    const struct region *e = (const struct region *) tag + tag->size;

    if (s < e) {
        return (size_t) (e - s);
    }
    return 0;
}

int main(void)
{
    struct tag t = {0, 0};

    return (int) region_span(&t);
}
