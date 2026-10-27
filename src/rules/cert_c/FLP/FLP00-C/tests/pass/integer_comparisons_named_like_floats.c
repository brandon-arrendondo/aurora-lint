/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS - integer comparisons, whatever the names
 *
 * The operands are typed by declaration: an int named `doubled`, an int
 * member of a struct that also has a double, and two ints.
 */

struct reading { double value; int count; };

int is_pair(int doubled) {
    return doubled == 2;
}

int is_empty(const struct reading *r) {
    return r->count == 0;
}

int same(int a, int b) {
    return a == b;
}
