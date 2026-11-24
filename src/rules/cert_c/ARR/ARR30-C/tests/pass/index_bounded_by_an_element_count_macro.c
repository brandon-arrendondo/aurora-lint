/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A guard against the element count a sizeof quotient macro spells bounds the index
 *
 * `ARRAY_SIZE(slots[row])` expands to `sizeof(slots[row]) /
 * sizeof((slots[row])[0])`, the count of a row of `slots`: 4. The search
 * leaves `idx` at most 4, and the early return removes 4 before either
 * access, so `idx` indexes a row in bounds. The macro's own `[0]` is a
 * `sizeof` operand and reads nothing. The loop in `clear_row` bounds `idx`
 * the same way on every pass.
 */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct slot {
    unsigned left;
};

static struct slot slots[5][4];

int take(int row)
{
    unsigned idx;

    row = !!row;
    for (idx = 0; idx < ARRAY_SIZE(slots[row]); idx++) {
        if (slots[row][idx].left != 0)
            break;
    }
    if (idx >= ARRAY_SIZE(slots[row]))
        return 0;
    slots[row][idx].left--;
    return 1;
}

void clear_row(void)
{
    unsigned idx = 0;

    while (idx < ARRAY_SIZE(slots[1])) {
        slots[1][idx].left = 0;
        idx++;
    }
}
