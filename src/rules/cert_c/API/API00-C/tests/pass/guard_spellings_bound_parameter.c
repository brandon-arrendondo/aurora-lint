/*
 * Rule: API00-C
 * Source: real-world (task 739)
 * Status: PASS - Should NOT trigger API00-C violation
 */

/*
 * Four ways an integer parameter is bounded that API00-C used to miss because
 * it searched the body text for one canonical spelling of a validation check
 * ("if (n < ", a comparison against INT_MAX/SIZE_MAX, __builtin_*_overflow).
 * Every function below bounds its parameter with an ordinary comparison, and
 * each is reduced from a real false positive in task 664's integer-overflow
 * adjudication sample.
 */

#include <limits.h>

/*
 * 1. Early-return guard against an ordinary operand, not a type maximum --
 *    and written without spaces around the operator, which is what actually
 *    defeated the text patterns.
 *    From sqlite src/main.c sqlite3_uri_key().
 */
int nth_key(const char *keys, int N)
{
    if (keys == 0 || N < 0)
        return 0;
    while (keys[0] && (N--) > 0)
        keys += 2;
    return keys[0];
}

/*
 * 2. Enclosing-branch range test: the guard DOMINATES the arithmetic rather
 *    than merely preceding it, and each else-if branch carries its own bound.
 *    From sqlite ext/fts3/fts3_unicode2.c sqlite3FtsUnicodeFold().
 */
int fold_codepoint(int c)
{
    int ret = c;
    if (c < 128) {
        if (c >= 'A' && c <= 'Z')
            ret = c + ('a' - 'A');
    } else if (c < 65536) {
        ret = (c - 65535) & 0x0000FFFF;
    } else if (c >= 66560 && c < 66600) {
        ret = c + 40;
    }
    return ret;
}

/*
 * 3. Loop-condition bound: `i < argc` in the for header proves argc >= 2 at
 *    the `argc - 1` in the body.
 *    From curl src/tool_getparam.c parse_args().
 */
int count_pairs(int argc)
{
    int i;
    int pairs = 0;
    for (i = 1; i < argc; i++) {
        if (i < (argc - 1))
            pairs++;
    }
    return pairs;
}

/*
 * 4. The negation-overflow check spelled as an equality against the type
 *    extreme -- the only value `-n` overflows on.
 *    From sqlite ext/fts5/fts5_index.c sqlite3Fts5IndexMerge().
 */
int absolute_merge_count(int nMerge)
{
    if (nMerge < 0) {
        nMerge = (nMerge == INT_MIN ? INT_MAX : (nMerge * -1));
    }
    return nMerge;
}

/*
 * Reversed operands and a compound (non-identifier) bound: neither side of the
 * comparison has to be the bare parameter.
 * From hostap src/utils/wpabuf.c wpabuf_array_remove().
 */
struct span {
    unsigned int num;
};

void shift_down(struct span *sp, unsigned int idx)
{
    if (!sp || sp->num == 0 || idx >= sp->num)
        return;
    while (idx + 1 < sp->num)
        idx++;
}

/*
 * A guard whose comparison bounds the parameter from the other direction, in a
 * preceding statement rather than an enclosing branch, proving the subtraction
 * cannot underflow.
 * From hostap src/crypto/crypto_internal-modexp.c crypto_dh_init().
 */
unsigned long padding_for(unsigned long have, unsigned long want)
{
    unsigned long pad = 0;
    if (have < want) {
        pad = want - have;
    }
    return pad;
}
