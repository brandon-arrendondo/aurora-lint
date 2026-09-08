/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. Consulting the argument
 * list for the outermost lvalue (task 1037) must answer the position actually
 * asked about, not suppress every field or element handed to a call: `s.vals`
 * passed to a function that only READS through the pointer, and a bare `n` at
 * a non-output position of a call whose FIRST argument is the output, are both
 * still uses of uninitialized storage.
 */
#include <string.h>

struct outer {
    int len;
    int vals[4];
};

extern void print_ints(const int *p, int n);

void use_int(int v);

/* s.vals reaches a reading callee — still a content read of s */
void field_passed_to_reader(void) {
    struct outer s;

    print_ints(s.vals, 4);
}

/* memset's first argument is the output; the length is not */
void length_arg_is_still_read(void) {
    struct outer s;
    int n;

    memset(s.vals, 0, n);
    use_int(s.vals[0]);
}
