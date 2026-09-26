/*
 * EXP14-C through a struct field whose tag another file also defines. This
 * file's `struct flags_holder` has an unsigned char `flags`, so `~s->flags`
 * promotes a type narrower than int and is reported. z_wide_field.c defines
 * the same tag with an unsigned int `flags`; the project-wide table keeps one
 * definition per tag, and the one in scope here is this file's own.
 */
struct flags_holder { unsigned char flags; };

void complement_field(struct flags_holder *s) {
    s->flags = ~s->flags;
}
