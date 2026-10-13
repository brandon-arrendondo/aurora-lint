/*
 * Rule: EXP34-C
 * Source: regression
 * Status: FAIL - a continue in a do loop carries its null pointer to the loop's exit
 *
 * A `continue` in a `do` body jumps to the condition, so when `k` is zero
 * the loop ends there with `p` still NULL, and the dereference after the
 * loop reads through it. Only the fallthrough path assigns `q`.
 */
#include <stddef.h>

int last(int c, int k, int *q) {
    int *p;
    do {
        p = NULL;
        if (c)
            continue;
        p = q;
    } while (k);
    return *p;
}
