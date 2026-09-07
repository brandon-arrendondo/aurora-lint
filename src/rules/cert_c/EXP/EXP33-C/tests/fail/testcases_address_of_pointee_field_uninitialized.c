/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `&p->n` is an address
 * inside the POINTEE, so computing it reads `p`, and a callee writing through
 * it says nothing about whether `p` was ever set. The address-of credit that
 * covers `&s.field` therefore stops at `->` -- otherwise hostap's intrusive
 * list macros (`dl_list_del(&x->list)`) would silence a genuinely unset `x`
 * (task 1028).
 */
#include <stdio.h>

struct node {
    int n;
};

extern void fill_int(int *p);

void use_int(int v);

void writes_through_unset_pointer(void) {
    struct node *p;

    fill_int(&p->n);
    use_int(p->n);
}
