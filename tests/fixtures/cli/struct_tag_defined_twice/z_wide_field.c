/*
 * The same struct tag as a_narrow_field.c, defined with a field of another
 * width. Named to sort after it, so a last-file-wins merge keeps this one.
 */
struct flags_holder { unsigned int flags; };

unsigned int get_flags(struct flags_holder *s) {
    return s->flags;
}
