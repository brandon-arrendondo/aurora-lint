/*
 * Rule: FIO44-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO44-C violation
 *
 * Each fsetpos() argument is the variable fgetpos() filled in its own
 * function. An fpos_t of the same name declared in a later function is a
 * different object, and a structure member is not known to be anything but
 * a value fgetpos() stored.
 */
#include <stdio.h>

struct saved_position {
    fpos_t pos;
};

int restore(FILE *fp) {
    fpos_t pos;
    if (fgetpos(fp, &pos) != 0) {
        return -1;
    }
    return fsetpos(fp, &pos);
}

void unrelated(void) {
    fpos_t pos;
    (void)pos;
}

int restore_member(FILE *fp, struct saved_position *saved) {
    return fsetpos(fp, &saved->pos);
}

int restore_struct(FILE *fp, struct saved_position saved) {
    return fsetpos(fp, &saved.pos);
}
