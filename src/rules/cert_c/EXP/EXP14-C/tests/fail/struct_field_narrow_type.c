/*
 * Rule: EXP14-C
 * Source: task-follow-up (post-fix recall regression fix)
 * Status: FAIL - Should trigger EXP14-C violation
 * Description: A narrow-typed struct field (a bitmask/capability field is
 * how a narrow operand most often appears in real code) must still be
 * recognized as narrower than int, not just a bare local variable.
 */

struct flags_holder {
    unsigned char flags;
    unsigned char items[8];
};

void complement_field(struct flags_holder *s) {
    s->flags = ~s->flags;
}

void shift_array_field(struct flags_holder *s, int i) {
    s->items[i] = s->items[i] << 2;
}
